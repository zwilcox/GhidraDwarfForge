package ghidradwarfforge.output;

import java.io.IOException;
import java.util.HashSet;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.BooleanSupplier;

import com.google.gson.stream.JsonWriter;
import ghidra.program.model.address.Address;
import ghidradwarfforge.AddressNormalizer;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.unwind.CallFramePlan;
import ghidradwarfforge.unwind.CallFramePlan.*;
import ghidradwarfforge.unwind.GhidraUnwindFrames.Observation;
import ghidradwarfforge.unwind.GhidraUnwindRecovery.Recovered;

/** Bounded description of captured recovery, not independent validation or a proof certificate. */
public final class UnwindEvidenceJson {
    private UnwindEvidenceJson() { }

    public static String describe(ElfImage image, Recovered recovered, long rebaseDelta,
            String inputSha256, String sidecarSha256, String sourceSha256,
            BooleanSupplier cancelled) throws IOException {
        return describe(image, recovered, rebaseDelta, inputSha256, sidecarSha256, sourceSha256,
            cancelled, ReportJsonReader.DEFAULT_LIMITS.bytes());
    }

    static String describe(ElfImage image, Recovered recovered, long rebaseDelta,
            String inputSha256, String sidecarSha256, String sourceSha256,
            BooleanSupplier cancelled, long byteLimit) throws IOException {
        check(cancelled);
        hash(inputSha256); hash(sidecarSha256); hash(sourceSha256);
        var instructions = validate(image, recovered, rebaseDelta, cancelled);
        var output = new CoverageReportJson.BoundedWriter(byteLimit, cancelled);
        try (var json = new JsonWriter(output)) {
            json.setSerializeNulls(true);
            json.beginObject();
            json.name("schemaVersion").value(1);
            json.name("kind").value("ghidra-unwind-evidence");
            json.name("provenance").value("instruction-and-ABI recovery; not original compiler facts");
            json.name("validationStatus").value("NOT_RUN");
            var separation = recovered.separation();
            json.name("memoryPolicy").value(separation.conditional() ?
                "explicitly conditioned absolute-range separation; other unresolved stores invalidate saved-memory evidence" :
                "unresolved stores invalidate saved-memory evidence");
            json.name("stackSeparation");
            if (!separation.conditional()) json.nullValue();
            else {
                json.beginObject().name("status").value("EXTERNAL_CONDITION_NOT_PROVED");
                json.name("basis").value(separation.basis());
                json.name("addressDomain").value("original ELF virtual address; apply runtime image load bias");
                json.name("ranges").beginArray();
                for (var region : separation.regions()) {
                    check(cancelled);
                    json.beginObject().name("first").value(hex(AddressNormalizer.toElfAddress(region.first(), rebaseDelta)));
                    json.name("last").value(hex(AddressNormalizer.toElfAddress(region.last(), rebaseDelta))).endObject();
                }
                json.endArray();
                json.name("fixedPointers").beginArray();
                for (var pointer : separation.fixedPointers()) {
                    check(cancelled);
                    json.beginObject().name("address").value(hex(AddressNormalizer.toElfAddress(pointer.address(), rebaseDelta)));
                    json.name("value").value(hex(AddressNormalizer.toElfAddress(pointer.value(), rebaseDelta))).endObject();
                }
                json.endArray().endObject();
            }
            json.name("inputSha256").value(inputSha256);
            json.name("sidecarSha256").value(sidecarSha256);
            json.name("sourceSha256").value(sourceSha256);
            json.name("elfMachine").value(image.machine());
            json.name("addressBytes").value(image.is64Bit() ? 8 : 4);
            json.name("byteOrder").value(image.byteOrder().toString());
            json.name("instructionAddressDomain").value("original ELF virtual address");
            json.name("databaseRebaseDelta").value(hex(rebaseDelta));
            json.name("hasPlan").value(recovered.plan().isPresent());
            json.name("verifiedFunctions").beginArray();
            for (var function : recovered.verifiedFunctions()) {
                check(cancelled); address(json, function);
            }
            json.endArray();
            json.name("refusedRoots").beginArray();
            for (var item : recovered.refusals().entrySet()) {
                check(cancelled);
                json.beginObject().name("function"); address(json, item.getKey());
                json.name("reason").value(item.getValue()).endObject();
            }
            json.endArray();
            json.name("observations").beginArray();
            for (var item : instructions.entrySet()) {
                check(cancelled);
                var observation = item.getValue();
                var bytes = recovered.originalBytes().get(observation.instruction());
                var projection = observation.projection();
                json.beginObject().name("function"); address(json, observation.function());
                json.name("instruction"); address(json, observation.instruction());
                json.name("address").value(hex(item.getKey()));
                json.name("bytes").value(observation.length());
                json.name("fileOffset").value(hex(bytes.fileOffset()));
                json.name("sha256").value(bytes.sha256());
                json.name("covered").value(projection.covered());
                json.name("omission").value(projection.omission());
                json.name("unavailableRegisters").beginArray();
                for (var unavailable : projection.unavailable().entrySet()) {
                    check(cancelled);
                    json.beginObject().name("register").value(unavailable.getKey());
                    json.name("reason").value(unavailable.getValue()).endObject();
                }
                json.endArray().endObject();
            }
            json.endArray();
            json.name("plan");
            if (recovered.plan().isEmpty()) json.nullValue();
            else {
                var plan = recovered.plan().orElseThrow();
                json.beginObject().name("returnRegister").value(plan.returnRegister());
                json.name("initialRules"); rules(json, plan.initialRules(), cancelled);
                json.name("frames").beginArray();
                for (var frame : plan.frames()) {
                    check(cancelled);
                    json.beginObject().name("address").value(hex(frame.address()));
                    json.name("bytes").value(Long.toString(frame.size()));
                    json.name("rows").beginArray();
                    for (var row : frame.rows()) {
                        check(cancelled);
                        json.beginObject().name("address").value(hex(row.address()));
                        json.name("cfa").beginObject().name("register").value(row.cfa().register());
                        json.name("offset").value(Long.toString(row.cfa().offset())).endObject();
                        json.name("rules"); rules(json, row.rules(), cancelled);
                        json.endObject();
                    }
                    json.endArray().endObject();
                }
                json.endArray().endObject();
            }
            json.endObject();
        }
        check(cancelled);
        return output.result();
    }

    private static TreeMap<Long, Observation> validate(ElfImage image, Recovered recovered,
            long delta, BooleanSupplier cancelled) {
        var separation = recovered.separation();
        if (separation.conditional()) {
            require(separation.addressBytes() == (image.is64Bit() ? 8 : 4), "separation condition target width differs");
            for (var region : separation.regions()) {
                check(cancelled);
                long first = AddressNormalizer.toElfAddress(region.first(), delta);
                long last = AddressNormalizer.toElfAddress(region.last(), delta);
                require(Long.compareUnsigned(first, last) <= 0 &&
                    (image.is64Bit() || Long.compareUnsigned(last, 0xffff_ffffL) <= 0),
                    "separation region wraps or exceeds original address width");
            }
        }
        for (var pointer : separation.fixedPointers()) {
            check(cancelled);
            long value = AddressNormalizer.toElfAddress(pointer.value(), delta);
            require(image.is64Bit() || Long.compareUnsigned(value, 0xffff_ffffL) <= 0,
                "fixed pointer value exceeds original address width");
        }
        require(recovered.verifiedFunctions().size() <= 65536 && recovered.refusals().size() <= 65536 &&
            recovered.observations().size() <= 1_000_000, "recovery report population exceeds bounds");
        require(recovered.observations().keySet().equals(recovered.originalBytes().keySet()),
            "recovery observations and original byte evidence differ");
        for (var refused : recovered.refusals().entrySet()) {
            check(cancelled);
            require(!recovered.verifiedFunctions().contains(refused.getKey()) &&
                refused.getValue() != null && !refused.getValue().isEmpty(), "invalid or conflicting root refusal");
        }
        var instructions = new TreeMap<Long, Observation>(Long::compareUnsigned);
        var covered = new HashSet<Long>();
        var owners = new HashSet<Address>();
        for (var item : recovered.observations().entrySet()) {
            check(cancelled);
            var observation = item.getValue();
            var bytes = recovered.originalBytes().get(item.getKey());
            long normalized = AddressNormalizer.toElfAddress(item.getKey().getOffset(), delta);
            require(item.getKey().equals(observation.instruction()) &&
                recovered.verifiedFunctions().contains(observation.function()), "observation owner/address mismatch");
            require(observation.length() > 0 && observation.length() <= 4096 &&
                bytes.bytes() == observation.length() && bytes.address() == normalized && bytes.fileOffset() >= 0,
                "observation has inconsistent original byte extent");
            hash(bytes.sha256());
            require(instructions.put(normalized, observation) == null, "duplicate original-image instruction");
            owners.add(observation.function());
            if (observation.projection().covered()) covered.add(normalized);
            else require(observation.projection().cfa() == null && observation.projection().rules().isEmpty() &&
                observation.projection().unavailable().isEmpty(), "omitted observation contains recovery claims");
        }
        require(owners.equals(recovered.verifiedFunctions()), "verified functions differ from observed owners");
        if (recovered.plan().isEmpty()) {
            require(instructions.isEmpty() && recovered.verifiedFunctions().isEmpty(), "unplanned verified recovery evidence");
            return instructions;
        }
        var plan = recovered.plan().orElseThrow();
        require(plan.addressBytes() == (image.is64Bit() ? 8 : 4) && plan.order() == image.byteOrder(),
            "frame plan target layout differs from report input");
        long priorEnd = 0; boolean first = true;
        for (var frame : plan.frames()) {
            check(cancelled);
            require(first || Long.compareUnsigned(frame.address(), priorEnd) > 0, "unordered or overlapping report frames");
            long cursor = frame.address();
            for (var row : frame.rows()) {
                check(cancelled);
                var observation = instructions.get(row.address());
                require(row.address() == cursor && observation != null && covered.remove(row.address()),
                    "frame row lacks unique contiguous instruction evidence");
                var projected = observation.projection();
                require(row.cfa().equals(projected.cfa()) && row.rules().equals(projected.rules()) &&
                    row.rules().keySet().equals(plan.registers()), "frame row differs from recovery projection");
                for (var missing : projected.unavailable().entrySet()) {
                    check(cancelled);
                    require(row.rules().get(missing.getKey()) instanceof Undefined &&
                        missing.getValue() != null && !missing.getValue().isEmpty(), "unavailable register has a recovery rule");
                }
                cursor += observation.length();
                require(Long.compareUnsigned(cursor - frame.address(), frame.size()) <= 0,
                    "instruction evidence extends past frame");
            }
            require(cursor - frame.address() == frame.size(), "frame contains unobserved trailing bytes");
            priorEnd = frame.address() + frame.size() - 1; first = false;
        }
        require(covered.isEmpty(), "covered observations are absent from frame plan");
        return instructions;
    }

    private static void rules(JsonWriter json, Map<Integer, Rule> rules, BooleanSupplier cancelled) throws IOException {
        json.beginArray();
        for (var entry : rules.entrySet()) {
            check(cancelled);
            json.beginObject().name("register").value(entry.getKey());
            var rule = entry.getValue();
            if (rule instanceof Undefined) json.name("kind").value("undefined");
            else if (rule instanceof SameValue) json.name("kind").value("sameValue");
            else if (rule instanceof InRegister other) {
                json.name("kind").value("inRegister").name("sourceRegister").value(other.register());
            }
            else if (rule instanceof AtCfaOffset saved) {
                json.name("kind").value("atCfaOffset").name("offset").value(Long.toString(saved.offset()));
            }
            else if (rule instanceof CfaValue value) {
                json.name("kind").value("cfaValue").name("offset").value(Long.toString(value.offset()));
            }
            else throw new IllegalArgumentException("unknown frame rule");
            json.endObject();
        }
        json.endArray();
    }

    private static void address(JsonWriter json, Address address) throws IOException {
        json.beginObject().name("space").value(address.getAddressSpace().getName());
        json.name("offset").value(hex(address.getOffset())).endObject();
    }
    private static String hex(long value) { return "0x" + Long.toUnsignedString(value, 16); }
    private static void hash(String hash) {
        require(hash != null && hash.matches("[0-9a-f]{64}"), "invalid unwind report SHA-256");
    }
    private static void check(BooleanSupplier cancelled) { ReportJsonReader.checkCancelled(cancelled); }
    private static void require(boolean condition, String message) {
        if (!condition) throw new IllegalArgumentException(message);
    }
}
