package ghidradwarfforge.output;

import com.google.gson.JsonParser;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidradwarfforge.elf.ElfCodeBytes.Match;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.unwind.CallFramePlan;
import ghidradwarfforge.unwind.CallFramePlan.*;
import ghidradwarfforge.unwind.GhidraUnwindFrames.Observation;
import ghidradwarfforge.unwind.GhidraUnwindRecovery.Recovered;
import ghidradwarfforge.unwind.UnwindFrameRows.Projected;
import ghidradwarfforge.unwind.UnwindStackSeparation;

/** Deliberately constructed consistency cases; no claim of recovered machine-code evidence. */
public final class UnwindEvidenceJsonBoundarySmoke {
    private static final String HASH = "a".repeat(64);
    private static final Cfa CFA = new Cfa(0, 8);
    private static final Map<Integer, Rule> RULES = Map.of(0, new CfaValue(0), 1, new Undefined());
    private static int checks;

    public static void main(String[] args) throws Exception {
        for (int width : new int[] {4, 8}) {
            for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                Path path = Files.createTempFile("forge-unwind-evidence-layout-", ".elf");
                try {
                    var header = ByteBuffer.allocate(width == 8 ? 64 : 52).order(order);
                    header.put(new byte[] {0x7f, 'E', 'L', 'F', (byte) (width == 8 ? 2 : 1),
                        (byte) (order == ByteOrder.LITTLE_ENDIAN ? 1 : 2), 1, 0});
                    header.putShort(16, (short) 2).putShort(18, (short) 8).putInt(20, 1);
                    header.putShort(width == 8 ? 52 : 40, (short) header.capacity());
                    Files.write(path, header.array());
                    byte[] original = Files.readAllBytes(path);
                    cases(ElfImage.read(path), width, order);
                    require(java.util.Arrays.equals(original, Files.readAllBytes(path)), "report changed original input");
                }
                finally { Files.delete(path); }
            }
        }
        System.out.println("unwind-evidence-boundaries=PASS checks=" + checks + " layouts=4");
    }

    private static void cases(ElfImage image, int width, ByteOrder order) throws Exception {
        var space = new GenericAddressSpace("ram", width * 8, AddressSpace.TYPE_RAM, 0);
        Address first = space.getAddress(0x1000), second = space.getAddress(0x1004), other = space.getAddress(0x2000);
        var projected = new Projected(CFA, RULES, Map.of(1, "unavailable incoming value"), "");
        var observed = new Observation(first, first, 4, projected);
        var plan = plan(width, order, List.of(new Frame(0x1000, 4, List.of(new Row(0x1000, CFA, RULES)))));
        var bytes = new Match(0x1000, 0x40, 4, HASH);
        var good = evidence(plan, first, Map.of(first, observed), Map.of(first, bytes));
        var json = JsonParser.parseString(describe(image, good, 0)).getAsJsonObject();
        require(json.get("addressBytes").getAsInt() == width, "wrong report address width");
        require(json.get("byteOrder").getAsString().equals(order.toString()), "wrong report byte order");
        var observation = json.getAsJsonArray("observations").get(0).getAsJsonObject();
        require(observation.get("address").getAsString().equals("0x1000") &&
            observation.get("fileOffset").getAsString().equals("0x40") &&
            observation.get("sha256").getAsString().equals(HASH), "observation identity changed");
        require(json.get("validationStatus").getAsString().equals("NOT_RUN"), "invented validation claim");

        for (int length : new int[] {-1, 0, 4097}) {
            refuse(() -> describe(image, evidence(plan, first,
                Map.of(first, new Observation(first, first, length, projected)), Map.of(first, bytes)), 0), "original byte extent");
        }
        for (Match invalid : List.of(new Match(0x1001, 0x40, 4, HASH), new Match(0x1000, -1, 4, HASH),
                new Match(0x1000, 0x40, 3, HASH))) {
            refuse(() -> describe(image, evidence(plan, first, Map.of(first, observed), Map.of(first, invalid)), 0), "original byte extent");
        }
        refuse(() -> describe(image, evidence(plan, first, Map.of(first, new Observation(other, first, 4, projected)),
            Map.of(first, bytes)), 0), "owner/address mismatch");
        refuse(() -> describe(image, evidence(plan, first, Map.of(first, new Observation(first, second, 4, projected)),
            Map.of(first, bytes)), 0), "owner/address mismatch");
        for (String hash : new String[] {null, "A".repeat(64), "b".repeat(63)}) {
            refuse(() -> describe(image, evidence(plan, first, Map.of(first, observed),
                Map.of(first, new Match(0x1000, 0x40, 4, hash))), 0), "SHA-256");
        }
        for (String reason : new String[] {null, ""}) {
            var refusals = new HashMap<Address, String>();
            refusals.put(other, reason);
            refuse(() -> describe(image, new Recovered(Optional.of(plan), Set.of(first), Map.of(first, observed),
                Map.of(first, bytes), refusals), 0), "root refusal");
        }

        var otherSpace = new GenericAddressSpace("overlay", width * 8, AddressSpace.TYPE_RAM, 1);
        var duplicate = otherSpace.getAddress(0x1000);
        refuse(() -> describe(image, evidence(plan, first, Map.of(first, observed,
            duplicate, new Observation(first, duplicate, 4, projected)),
            Map.of(first, bytes, duplicate, bytes)), 0), "duplicate original-image instruction");
        for (Projected invalid : List.of(new Projected(CFA, Map.of(), Map.of(), "omitted"),
                new Projected(null, RULES, Map.of(), "omitted"),
                new Projected(null, Map.of(), Map.of(1, "unavailable"), "omitted"))) {
            refuse(() -> describe(image, evidence(plan, first, Map.of(first, observed,
                second, new Observation(first, second, 4, invalid)),
                Map.of(first, bytes, second, new Match(0x1004, 0x44, 4, HASH))), 0), "omitted observation");
        }
        for (String reason : new String[] {null, ""}) {
            var unavailable = new HashMap<Integer, String>();
            unavailable.put(1, reason);
            refuse(() -> describe(image, evidence(plan, first, Map.of(first,
                new Observation(first, first, 4, new Projected(CFA, RULES, unavailable, ""))),
                Map.of(first, bytes)), 0), "unavailable register");
        }
        refuse(() -> describe(image, evidence(plan, first, Map.of(first,
            new Observation(first, first, 4, new Projected(CFA, RULES, Map.of(0, "unavailable"), ""))),
            Map.of(first, bytes)), 0), "unavailable register");

        for (CallFramePlan invalid : List.of(plan(width == 8 ? 4 : 8, order, plan.frames()),
                plan(width, order == ByteOrder.LITTLE_ENDIAN ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN, plan.frames()))) {
            refuse(() -> describe(image, evidence(invalid, first, Map.of(first, observed), Map.of(first, bytes)), 0), "target layout");
        }
        var mismatch = plan(width, order, List.of(new Frame(0x1000, 4,
            List.of(new Row(0x1000, CFA, Map.of(0, new CfaValue(16), 1, new Undefined()))))));
        refuse(() -> describe(image, evidence(mismatch, first, Map.of(first, observed), Map.of(first, bytes)), 0), "recovery projection");
        var largerUniverse = Map.<Integer, Rule>of(0, new CfaValue(0), 1, new Undefined(), 2, new Undefined());
        var missingRule = new CallFramePlan(width, order, 1, largerUniverse.keySet(), largerUniverse, plan.frames());
        refuse(() -> describe(image, evidence(missingRule, first, Map.of(first, observed), Map.of(first, bytes)), 0), "recovery projection");
        var overrun = plan(width, order, List.of(new Frame(0x1000, 3, List.of(new Row(0x1000, CFA, RULES)))));
        refuse(() -> describe(image, evidence(overrun, first, Map.of(first, observed), Map.of(first, bytes)), 0), "extends past frame");
        var missing = plan(width, order, List.of(new Frame(0x1004, 4, List.of(new Row(0x1004, CFA, RULES)))));
        refuse(() -> describe(image, evidence(missing, first, Map.of(first, observed), Map.of(first, bytes)), 0), "contiguous instruction evidence");
        var duplicated = plan(width, order, List.of(plan.frames().getFirst(), plan.frames().getFirst()));
        refuse(() -> describe(image, evidence(duplicated, first, Map.of(first, observed), Map.of(first, bytes)), 0), "overlapping report frames");
        var extra = new Observation(first, second, 4, projected);
        refuse(() -> describe(image, evidence(plan, first, Map.of(first, observed, second, extra),
            Map.of(first, bytes, second, new Match(0x1004, 0x44, 4, HASH))), 0), "absent from frame plan");

        long limit = width == 4 ? 0xffff_ffffL : -1L;
        var condition = new UnwindStackSeparation(width,
            List.of(new UnwindStackSeparation.Region(limit - 15, limit)), "explicit fixture condition");
        var conditional = new Recovered(Optional.empty(), Set.of(), Map.of(), Map.of(), Map.of(), condition);
        var range = JsonParser.parseString(describe(image, conditional, 0)).getAsJsonObject()
            .getAsJsonObject("stackSeparation").getAsJsonArray("ranges").get(0).getAsJsonObject();
        require(range.get("last").getAsString().equals(width == 4 ? "0xffffffff" : "0xffffffffffffffff"),
            "unsigned conditional range changed");
        if (width == 4) {
            refuse(() -> describe(image, conditional, -16), "original address width");
            var fixed = new UnwindStackSeparation(4, List.of(new UnwindStackSeparation.Region(0x1000, 0x1003)),
                "explicit pointer condition", List.of(new UnwindStackSeparation.Pointer(0x1000, 0xffff_fff0L)));
            var pointer = new Recovered(Optional.empty(), Set.of(), Map.of(), Map.of(), Map.of(), fixed);
            refuse(() -> describe(image, pointer, -32), "pointer value exceeds original address width");
        }
    }

    private static CallFramePlan plan(int width, ByteOrder order, List<Frame> frames) {
        return new CallFramePlan(width, order, 1, RULES.keySet(), RULES, frames);
    }

    private static Recovered evidence(CallFramePlan plan, Address owner, Map<Address, Observation> observations,
            Map<Address, Match> bytes) {
        return new Recovered(Optional.of(plan), Set.of(owner), observations, bytes, Map.of());
    }

    private static String describe(ElfImage image, Recovered recovered, long delta) throws Exception {
        return UnwindEvidenceJson.describe(image, recovered, delta, HASH, HASH, HASH, () -> false);
    }

    @FunctionalInterface private interface Action { void run() throws Exception; }
    private static void refuse(Action action, String diagnostic) throws Exception {
        try { action.run(); throw new AssertionError("inconsistent evidence accepted: " + diagnostic); }
        catch (IllegalArgumentException | java.io.IOException expected) {
            require(expected.getMessage().contains(diagnostic), "wrong refusal: " + expected);
        }
    }
    private static void require(boolean value, String message) {
        if (!value) throw new AssertionError(message);
        checks++;
    }
}
