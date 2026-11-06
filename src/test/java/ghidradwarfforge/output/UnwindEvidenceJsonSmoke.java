package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CancellationException;

import com.google.gson.JsonParser;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.elf.ElfCodeBytes.Match;
import ghidradwarfforge.unwind.CallFramePlan;
import ghidradwarfforge.unwind.UnwindStackSeparation;
import ghidradwarfforge.unwind.CallFramePlan.*;
import ghidradwarfforge.unwind.GhidraUnwindFrames.Observation;
import ghidradwarfforge.unwind.GhidraUnwindRecovery.Recovered;
import ghidradwarfforge.unwind.UnwindFrameRows.Projected;

/** Description/consistency tests; these constructed rows are not recovery evidence. */
public final class UnwindEvidenceJsonSmoke {
    private static final String HASH = "a".repeat(64);
    private static int checks;
    @FunctionalInterface private interface Action { void run() throws Exception; }
    private static void require(boolean condition, String message) { if (!condition) throw new AssertionError(message); checks++; }
    private static void reject(Action action) throws Exception {
        try { action.run(); throw new AssertionError("invalid report evidence accepted"); }
        catch (IllegalArgumentException | IOException expected) { checks++; }
    }
    private static String describe(ElfImage image, Recovered recovered, long delta) throws IOException {
        return UnwindEvidenceJson.describe(image, recovered, delta, HASH, HASH, HASH, () -> false);
    }
    public static void main(String[] args) throws Exception {
        var path = Files.createTempFile("forge-unwind-report-", ".elf");
        try {
            var bytes = ByteBuffer.allocate(64).order(ByteOrder.LITTLE_ENDIAN);
            bytes.put(new byte[] {0x7f, 'E', 'L', 'F', 2, 1, 1, 0});
            bytes.putShort(16, (short) 2).putShort(18, (short) 62).putInt(20, 1).putShort(52, (short) 64);
            Files.write(path, bytes.array());
            var image = ElfImage.read(path);
            var space = new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0);
            var first = space.getAddress(0x401000);
            var second = space.getAddress(0x401004);
            var refused = space.getAddress(0x402000);
            Map<Integer, Rule> rules = Map.of(0, new CfaValue(0), 1, new AtCfaOffset(-8),
                2, new SameValue(), 3, new InRegister(2), 4, new Undefined());
            var cfa = new Cfa(0, 8);
            var projection = new Projected(cfa, rules, Map.of(4, "unknown incoming identity"), "");
            var omission = new Projected(null, Map.of(), Map.of(), "original frame coverage takes precedence");
            var observation = new Observation(first, first, 4, projection);
            var omitted = new Observation(first, second, 4, omission);
            var plan = new CallFramePlan(8, ByteOrder.LITTLE_ENDIAN, 1, rules.keySet(), rules,
                List.of(new Frame(0x1000, 4, List.of(new Row(0x1000, cfa, rules)))));
            var matches = Map.of(first, new Match(0x1000, 64, 4, HASH), second, new Match(0x1004, 68, 4, HASH));
            String reason = "unproved \"effect\"\nΩ 😃";
            var recovered = new Recovered(Optional.of(plan), Set.of(first), Map.of(second, omitted, first, observation),
                matches, Map.of(refused, reason));
            String text = describe(image, recovered, 0x400000);
            var json = JsonParser.parseString(text).getAsJsonObject();
            require(json.get("validationStatus").getAsString().equals("NOT_RUN"), "report claims validation");
            require(json.getAsJsonArray("refusedRoots").get(0).getAsJsonObject().get("reason").getAsString().equals(reason),
                "refusal text changed");
            var observations = json.getAsJsonArray("observations");
            require(observations.size() == 2 && observations.get(0).getAsJsonObject().get("address").getAsString().equals("0x1000"),
                "normalized observation order/address wrong");
            require(!observations.get(1).getAsJsonObject().get("covered").getAsBoolean(), "original coverage invented a generated row");
            var rows = json.getAsJsonObject("plan").getAsJsonArray("frames").get(0).getAsJsonObject().getAsJsonArray("rows");
            require(rows.size() == 1 && rows.get(0).getAsJsonObject().getAsJsonArray("rules").size() == 5, "rule rows lost");
            require(text.equals(describe(image, recovered, 0x400000)), "nondeterministic report");
            int length = text.getBytes(StandardCharsets.UTF_8).length;
            require(text.equals(UnwindEvidenceJson.describe(image, recovered, 0x400000, HASH, HASH, HASH, () -> false, length)),
                "exact UTF-8 bound rejected");
            reject(() -> UnwindEvidenceJson.describe(image, recovered, 0x400000, HASH, HASH, HASH, () -> false, length - 1));
            reject(() -> describe(image, recovered, 0));
            reject(() -> UnwindEvidenceJson.describe(image, recovered, 0x400000, "bad", HASH, HASH, () -> false));
            reject(() -> describe(image, new Recovered(Optional.empty(), Set.of(first), recovered.observations(), matches, Map.of()), 0x400000));
            reject(() -> describe(image, new Recovered(Optional.of(plan), Set.of(first, refused), recovered.observations(), matches, Map.of()), 0x400000));
            reject(() -> describe(image, new Recovered(Optional.of(plan), Set.of(first), recovered.observations(),
                Map.of(first, matches.get(first)), Map.of()), 0x400000));
            reject(() -> describe(image, new Recovered(Optional.of(plan), Set.of(first), recovered.observations(),
                Map.of(first, new Match(0x1000, 64, 3, HASH), second, matches.get(second)), Map.of()), 0x400000));
            reject(() -> describe(image, new Recovered(Optional.of(plan), Set.of(first), recovered.observations(), matches,
                Map.of(first, "also refused")), 0x400000));
            var wrong = new Projected(new Cfa(2, 8), rules, Map.of(), "");
            reject(() -> describe(image, new Recovered(Optional.of(plan), Set.of(first),
                Map.of(first, new Observation(first, first, 4, wrong), second, omitted), matches, Map.of()), 0x400000));
            var gap = new CallFramePlan(8, ByteOrder.LITTLE_ENDIAN, 1, rules.keySet(), rules,
                List.of(new Frame(0x1000, 8, List.of(new Row(0x1000, cfa, rules)))));
            reject(() -> describe(image, new Recovered(Optional.of(gap), Set.of(first), recovered.observations(), matches, Map.of()), 0x400000));
            var noPlan = new Recovered(Optional.empty(), Set.of(), Map.of(), Map.of(), Map.of(refused, reason));
            require(JsonParser.parseString(describe(image, noPlan, 0)).getAsJsonObject().get("plan").isJsonNull(),
                "refusal-only report invents a plan");
            require(json.get("stackSeparation").isJsonNull(), "strict report invents a separation condition");
            var condition = new UnwindStackSeparation(8,
                List.of(new UnwindStackSeparation.Region(0x403000, 0x403007)), "external test basis Ω 😃",
                List.of(new ghidradwarfforge.unwind.UnwindStackSeparation.Pointer(0x403000, 0x405000)));
            var conditioned = new Recovered(recovered.plan(), recovered.verifiedFunctions(), recovered.observations(),
                recovered.originalBytes(), recovered.refusals(), condition);
            String conditionalText = describe(image, conditioned, 0x400000);
            var conditionalJson = JsonParser.parseString(conditionalText).getAsJsonObject();
            var separationJson = conditionalJson.getAsJsonObject("stackSeparation");
            require(separationJson.get("status").getAsString().equals("EXTERNAL_CONDITION_NOT_PROVED"),
                "conditional report claims proof of separation");
            require(separationJson.get("basis").getAsString().equals(condition.basis()), "external basis changed");
            require(conditionalJson.get("validationStatus").getAsString().equals("NOT_RUN"), "conditional report claims validation");
            require(!conditionalJson.get("memoryPolicy").equals(json.get("memoryPolicy")), "conditional policy labeled strict");
            var regionJson = separationJson.getAsJsonArray("ranges").get(0).getAsJsonObject();
            require(regionJson.get("first").getAsString().equals("0x3000") && regionJson.get("last").getAsString().equals("0x3007"),
                "condition was not normalized with frame addresses");
            var pointerJson = separationJson.getAsJsonArray("fixedPointers").get(0).getAsJsonObject();
            require(pointerJson.get("address").getAsString().equals("0x3000") &&
                pointerJson.get("value").getAsString().equals("0x5000"), "fixed pointer normalization lost condition");
            int conditionalLength = conditionalText.getBytes(StandardCharsets.UTF_8).length;
            require(conditionalText.equals(UnwindEvidenceJson.describe(image, conditioned, 0x400000, HASH, HASH, HASH,
                () -> false, conditionalLength)), "exact conditional UTF-8 bound rejected");
            reject(() -> UnwindEvidenceJson.describe(image, conditioned, 0x400000, HASH, HASH, HASH,
                () -> false, conditionalLength - 1));
            for (var invalid : List.of(
                    new UnwindStackSeparation(4, condition.regions(), condition.basis()),
                    new UnwindStackSeparation(8, List.of(new UnwindStackSeparation.Region(0x3fffff, 0x400001)), condition.basis()))) {
                reject(() -> describe(image, new Recovered(recovered.plan(), recovered.verifiedFunctions(), recovered.observations(),
                    recovered.originalBytes(), recovered.refusals(), invalid), 0x400000));
            }
            // Exercise cancellation at every output/provenance boundary on both policies.
            for (var candidate : List.of(recovered, conditioned)) {
                String expectedText = describe(image, candidate, 0x400000);
                int[] polls = {0};
                require(expectedText.equals(UnwindEvidenceJson.describe(image, candidate, 0x400000, HASH, HASH, HASH,
                    () -> { polls[0]++; return false; })), "counting changed report");
                for (int stop = 1; stop <= polls[0]; stop++) {
                    int selected = stop; int[] count = {0};
                    try {
                        UnwindEvidenceJson.describe(image, candidate, 0x400000, HASH, HASH, HASH, () -> ++count[0] == selected);
                        throw new AssertionError("report ignored cancellation");
                    }
                    catch (CancellationException expected) { checks++; }
                }
                require(expectedText.equals(describe(image, candidate, 0x400000)), "cancelled report poisoned retry");
            }
        }
        finally { Files.delete(path); }
        System.out.println("unwind-evidence-json-smoke=PASS checks=" + checks);
    }
}
