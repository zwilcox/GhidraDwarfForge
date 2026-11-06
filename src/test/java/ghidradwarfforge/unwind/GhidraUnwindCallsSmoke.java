package ghidradwarfforge.unwind;

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import ghidradwarfforge.dwarf.DwarfDebugFrame;
import ghidradwarfforge.unwind.CallFramePlan.*;

import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.address.AddressSet;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.elf.ElfImage;

/** Actual native direct/self/mutual call decoding and counterexamples. */
public final class GhidraUnwindCallsSmoke {
    private static int checks;
    private static final StringBuilder evidence = new StringBuilder();
    private static Path output;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        output = Path.of(args[1]); Files.createDirectories(output);
        for (boolean arm : List.of(false, true)) {
            for (String shape : List.of("leaf", "direct", "self", "mutual", "gap", "unreachable", "patched", "clobber", "unknown-write", "bad-stack", "missing", "indirect", "custom")) {
                run(arm, shape);
            }
            mixed(arm);
        }
        Files.writeString(output.resolve("native.txt"), evidence.toString());
        System.out.println("ghidra-unwind-calls-smoke=PASS checks=" + checks);
    }
    private static void require(boolean test, String reason) {
        if (!test) throw new AssertionError(reason);
        checks++;
    }
    private static String word(int value) {
        return HexFormat.of().formatHex(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value).array());
    }
    private static String call(boolean arm, int address, int target) {
        return arm ? word(0x94000000 | ((target - address) >> 2) & 0x03ffffff) : "e8" + word(target - address - 5);
    }
    private static String caller(boolean arm, int address, int target, boolean recursive) {
        if (arm) return "f37bbfa9" + (recursive ? "600000b4000400d1" : "") +
            call(true, address + (recursive ? 12 : 4), target) + "f37bc1a8c0035fd6";
        return "4154" + (recursive ? "4885ff74094883ef01" : "") +
            call(false, address + (recursive ? 11 : 2), target) + "415cc3";
    }
    private static ElfImage image(boolean arm, String tag, Map<Integer, String> source) throws Exception {
        int headerEnd = 64 + 56 * source.size();
        var bytes = ByteBuffer.allocate(headerEnd + source.values().stream().mapToInt(hex -> hex.length() / 2).sum())
            .order(ByteOrder.LITTLE_ENDIAN);
        bytes.put(new byte[] {0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0});
        bytes.putShort(16, (short) 2).putShort(18, (short) (arm ? 183 : 62)).putInt(20, 1);
        bytes.putLong(24, 0x9000).putShort(52, (short) 64);
        bytes.putLong(32, 64).putShort(54, (short) 56).putShort(56, (short) source.size());
        int offset = headerEnd, index = 0;
        for (var item : source.entrySet()) {
            byte[] code = HexFormat.of().parseHex(item.getValue());
            int position = 64 + 56 * index++;
            bytes.putInt(position, 1).putInt(position + 4, 5).putLong(position + 8, offset)
                .putLong(position + 16, item.getKey()).putLong(position + 32, code.length)
                .putLong(position + 40, code.length).putLong(position + 48, 1);
            bytes.position(offset); bytes.put(code); offset += code.length;
        }
        Path path = output.resolve(tag + ".elf"); Files.write(path, bytes.array());
        return ElfImage.read(path);
    }
    private static ElfImage framed(ElfImage original, String name, long[][] ranges) throws Exception {
        var frames = new java.util.ArrayList<Frame>();
        for (var range : ranges) frames.add(new Frame(range[0], range[1], List.of(
            new Row(range[0], new Cfa(0, 8), Map.of(0, new CfaValue(0), 1, new AtCfaOffset(-8))))));
        byte[] data = DwarfDebugFrame.build(new CallFramePlan(8, ByteOrder.LITTLE_ENDIAN, 1, Set.of(0, 1),
            Map.of(0, new Undefined(), 1, new Undefined()), frames), () -> false);
        byte[] names = "\0.shstrtab\0.debug_frame\0".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] old = original.bytes();
        int namesAt = old.length, dataAt = namesAt + names.length, table = dataAt + data.length;
        var out = ByteBuffer.allocate(table + 3 * 64).order(ByteOrder.LITTLE_ENDIAN);
        out.put(old).put(names).put(data);
        out.putLong(40, table).putShort(58, (short) 64).putShort(60, (short) 3).putShort(62, (short) 1);
        out.putInt(table + 64, 1).putInt(table + 68, 3).putLong(table + 88, namesAt)
            .putLong(table + 96, names.length).putLong(table + 112, 1);
        out.putInt(table + 128, 11).putInt(table + 132, 1).putLong(table + 152, dataAt)
            .putLong(table + 160, data.length).putLong(table + 176, 1);
        Path path = output.resolve(name + ".elf"); Files.write(path, out.array());
        return ElfImage.read(path);
    }
    @FunctionalInterface private interface CheckedAction { void run() throws Exception; }
    private static void refuses(CheckedAction action, String message) throws Exception {
        try { action.run(); throw new AssertionError("conditional evidence accepted without exact acknowledgement"); }
        catch (IllegalArgumentException expected) { require(expected.getMessage().equals(message), "wrong conditional refusal: " + expected); }
    }
    private static void conditioned(ProgramDB program, Function root, ElfImage image,
            GhidraUnwindFrames.Planned strict) throws Exception {
        var condition = new UnwindStackSeparation(8, List.of(new UnwindStackSeparation.Region(0x3000, 0x3007)),
            "explicit unused test condition");
        var proof = GhidraUnwindCalls.verify(program, root, image, 0, TaskMonitor.DUMMY, condition);
        refuses(() -> GhidraUnwindFrames.plan(proof, 0, TaskMonitor.DUMMY),
            "conditional stack separation requires an explicit qualified projection path");
        for (var wrong : List.of(UnwindStackSeparation.NONE,
                new UnwindStackSeparation(8, condition.regions(), "different basis"),
                new UnwindStackSeparation(8, List.of(new UnwindStackSeparation.Region(0x3000, 0x3006)), condition.basis()))) {
            refuses(() -> GhidraUnwindFrames.planConditioned(proof, 0, TaskMonitor.DUMMY, wrong),
                "conditional projection requires the exact accepted separation condition");
        }
        var planned = GhidraUnwindFrames.planConditioned(proof, 0, TaskMonitor.DUMMY, condition);
        require(planned.separation().equals(condition) && strict.separation().equals(UnwindStackSeparation.NONE),
            "projection changed policy provenance");
        require(planned.plan().equals(strict.plan()) && planned.observations().equals(strict.observations()),
            "unused condition changed frame rules");
        var collected = GhidraUnwindRecovery.recoverConditioned(program, image, 0, TaskMonitor.DUMMY, condition);
        require(collected.separation().equals(condition) && collected.plan().orElseThrow().equals(strict.plan()),
            "conditioned collection lost condition or changed rules");
        refuses(() -> GhidraUnwindRecovery.recoverConditioned(program, image, 0, TaskMonitor.DUMMY, UnwindStackSeparation.NONE),
            "conditioned collection requires an external condition");
        int[] polls = {0};
        var counting = new TaskMonitorAdapter() {
            @Override public void checkCancelled() throws CancelledException { polls[0]++; }
        };
        require(GhidraUnwindFrames.planConditioned(proof, 0, counting, condition).equals(planned), "counted projection changed");
        for (int stop = 1; stop <= polls[0]; stop++) {
            int selected = stop; int[] count = {0};
            var cancelling = new TaskMonitorAdapter() {
                @Override public void checkCancelled() throws CancelledException {
                    if (++count[0] == selected) throw new CancelledException();
                }
            };
            try {
                GhidraUnwindFrames.planConditioned(proof, 0, cancelling, condition);
                throw new AssertionError("conditional projection ignored cancellation");
            }
            catch (CancelledException expected) { checks++; }
        }
        require(GhidraUnwindFrames.planConditioned(proof, 0, TaskMonitor.DUMMY, condition).equals(planned),
            "cancelled conditional projection poisoned retry");
    }
    private static void run(boolean arm, String shape) throws Exception {
        String tag = (arm ? "aarch64" : "x86") + "-" + shape;
        String leaf = arm ? "c0035fd6" : "c3";
        var source = new LinkedHashMap<Integer, String>();
        switch (shape) {
            case "leaf" -> source.put(0x1000, leaf);
            case "patched" -> source.put(0x1000, arm ? "f37bbfa9f37bc1a8c0035fd6" : "4154415cc3");
            case "gap", "unreachable" -> source.put(0x1000, arm ? "020000141f2003d5c0035fd6" : "eb0190c3");
            case "self" -> source.put(0x1000, caller(arm, 0x1000, 0x1000, true));
            case "mutual" -> {
                source.put(0x1000, caller(arm, 0x1000, 0x1100, true));
                source.put(0x1100, caller(arm, 0x1100, 0x1000, true));
            }
            case "indirect" -> source.put(0x1000, (arm ? "00003fd6" : "ffd0") + leaf);
            default -> {
                source.put(0x1000, caller(arm, 0x1000, 0x1100, false));
                if (!shape.equals("missing")) source.put(0x1100, switch (shape) {
                    case "clobber" -> (arm ? "330580d2" : "49c7c42a000000") + leaf;
                    case "unknown-write" -> (arm ? "200000f9" : "488907") + leaf;
                    case "bad-stack" -> arm ? "ff430091" + leaf : "c20800";
                    default -> leaf;
                });
            }
        }
        var language = DefaultLanguageService.getLanguageService().getLanguage(
            new LanguageID(arm ? "AARCH64:LE:64:v8A" : "x86:LE:64:default"));
        Object owner = new Object();
        var program = new ProgramDB(tag, language, language.getCompilerSpecByID(new CompilerSpecID(arm ? "default" : "gcc")), owner);
        try {
            int transaction = program.startTransaction("native callee fixture");
            try {
                var functions = new LinkedHashMap<Integer, Function>();
                for (var item : source.entrySet()) {
                    byte[] bytes = HexFormat.of().parseHex(item.getValue());
                    if (shape.equals("patched")) bytes[arm ? 0 : 1]++;
                    var entry = language.getDefaultSpace().getAddress(item.getKey());
                    program.getMemory().createInitializedBlock("text" + item.getKey(), entry, bytes.length,
                        (byte) 0, TaskMonitor.DUMMY, false).setExecute(true);
                    program.getMemory().setBytes(entry, bytes);
                }
                for (var item : source.entrySet()) {
                    var entry = language.getDefaultSpace().getAddress(item.getKey());
                    var body = new AddressSet(entry, entry.add(item.getValue().length() / 2 - 1));
                    if (shape.equals("gap")) body.delete(entry.add(arm ? 4 : 2), entry.add(arm ? 7 : 2));
                    require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY), "decode " + tag);
                    if (shape.equals("unreachable")) require(new DisassembleCommand(entry.add(arm ? 4 : 2), body, true)
                        .applyTo(program, TaskMonitor.DUMMY), "decode unreachable fixture instruction");
                    functions.put(item.getKey(), program.getFunctionManager().createFunction("callee_" + item.getKey(), entry, body, SourceType.USER_DEFINED));
                }
                if (shape.equals("custom")) functions.get(0x1100).setCustomVariableStorage(true);
                ElfImage image = image(arm, tag, source);
                byte[] originalImage = image.bytes();
                boolean positive = List.of("leaf", "direct", "self", "mutual", "gap", "unreachable").contains(shape);
                try {
                    var proof = GhidraUnwindCalls.verify(program, functions.get(0x1000), image, 0, TaskMonitor.DUMMY);
                    require(positive, "unsupported native callee accepted: " + tag);
                    require(proof.verified().bodies().size() == source.size(), "native closure omitted a callee");
                    require(proof.originalBytes().size() == proof.captures().values().stream()
                        .mapToInt(capture -> capture.observations().size()).sum(), "original byte agreement omitted an instruction");
                    var planned = GhidraUnwindFrames.plan(proof, 0, TaskMonitor.DUMMY);
                    if (shape.equals("direct")) conditioned(program, functions.get(0x1000), image, planned);
                    var collected = GhidraUnwindRecovery.recover(program, image, 0, TaskMonitor.DUMMY);
                    require(collected.refusals().isEmpty() && collected.plan().orElseThrow().equals(planned.plan()) &&
                        collected.originalBytes().equals(proof.originalBytes()), "program collection changed a proved group");
                    require(planned.plan().frames().size() == (shape.equals("gap") || shape.equals("unreachable") ? 2 : source.size()),
                        "frame coverage bridged a body gap or omitted a callee");
                    require(planned.observations().stream().filter(row -> !row.projection().covered()).count() ==
                        (shape.equals("unreachable") ? 1 : 0), "unreachable coverage was not explicitly omitted");
                    for (var frame : planned.plan().frames()) {
                        for (var row : frame.rows()) require(row.rules().keySet().equals(planned.plan().registers()), "partial initial row rules");
                    }
                    if (shape.equals("gap") || shape.equals("unreachable")) {
                        require(planned.plan().frames().get(0).size() == (arm ? 4 : 2) &&
                            planned.plan().frames().get(1).address() == (arm ? 0x1008 : 0x1003), "unknown interval covered by previous frame row");
                    }
                    for (var item : proof.captures().entrySet()) {
                        evidence.append(tag).append(" function=").append(item.getKey()).append('\n');
                        item.getValue().observations().forEach((address, observation) ->
                            evidence.append(address).append(' ').append(observation).append('\n'));
                    }
                    evidence.append("flow=").append(proof.verified().flows()).append('\n');
                    if (shape.equals("direct")) {
                        long callAddress = arm ? 0x1004 : 0x1002;
                        ElfImage partial = framed(image, tag + "-original-partial", new long[][] {{callAddress + 1, 1}});
                        var partialProof = GhidraUnwindCalls.verify(program, functions.get(0x1000), partial, 0, TaskMonitor.DUMMY);
                        var partialPlan = GhidraUnwindFrames.plan(partialProof, 0, TaskMonitor.DUMMY);
                        require(partialPlan.plan().frames().size() == 3, "original partial coverage did not split generated ranges");
                        require(partialPlan.observations().stream().filter(row -> !row.projection().covered()).count() == 1,
                            "partial original coverage did not omit exactly one whole instruction");
                        require(partialPlan.observations().stream().anyMatch(row -> row.instruction().getOffset() == callAddress &&
                            row.projection().omission().equals("original frame coverage takes precedence")), "missing original precedence diagnostic");
                        for (var frame : partialPlan.plan().frames()) require(frame.address() + frame.size() <= callAddress ||
                            frame.address() >= callAddress + (arm ? 4 : 5), "synthesized row overlaps original-covered instruction");
                        ElfImage full = framed(image, tag + "-original-full", source.entrySet().stream()
                            .map(item -> new long[] {item.getKey(), item.getValue().length() / 2}).toArray(long[][]::new));
                        var fullProof = GhidraUnwindCalls.verify(program, functions.get(0x1000), full, 0, TaskMonitor.DUMMY);
                        require(GhidraUnwindFrames.plan(fullProof, 0, TaskMonitor.DUMMY).plan().frames().isEmpty(),
                            "original full coverage did not suppress synthesis");
                        var covered = GhidraUnwindRecovery.recover(program, full, 0, TaskMonitor.DUMMY);
                        require(covered.plan().orElseThrow().frames().isEmpty() && covered.refusals().isEmpty() &&
                            covered.verifiedFunctions().size() == source.size(), "collection lost original-frame precedence");
                        ElfImage unrelated = framed(image, tag + "-original-unrelated", new long[][] {{0x2000, 32}});
                        var unrelatedProof = GhidraUnwindCalls.verify(program, functions.get(0x1000), unrelated, 0, TaskMonitor.DUMMY);
                        require(GhidraUnwindFrames.plan(unrelatedProof, 0, TaskMonitor.DUMMY).equals(planned),
                            "unrelated original coverage suppressed valid recovered frames");
                        var coverage = partialProof.originalCoverage();
                        require(coverage.overlaps(callAddress, 2) && !coverage.overlaps(callAddress, 1) &&
                            !coverage.overlaps(callAddress + 2, 1), "original coverage half-open boundary");
                        int[] coveragePolls = {0};
                        ghidradwarfforge.elf.OriginalUnwindCoverage.inspect(partial, () -> { coveragePolls[0]++; return false; });
                        for (int stopAt = 1; stopAt <= coveragePolls[0]; stopAt++) {
                            int stop = stopAt; int[] seen = {0};
                            try {
                                ghidradwarfforge.elf.OriginalUnwindCoverage.inspect(partial, () -> ++seen[0] == stop);
                                throw new AssertionError("original coverage cancellation ignored");
                            }
                            catch (java.util.concurrent.CancellationException expected) { checks++; }
                        }
                        require(ghidradwarfforge.elf.OriginalUnwindCoverage.inspect(partial, () -> false).intervals().equals(coverage.intervals()),
                            "original coverage cancellation poisoned retry");
                        byte[] malformed = partial.bytes();
                        var broken = ByteBuffer.wrap(malformed).order(ByteOrder.LITTLE_ENDIAN);
                        int sectionTable = Math.toIntExact(broken.getLong(40));
                        int frameOffset = Math.toIntExact(broken.getLong(sectionTable + 152));
                        broken.putInt(frameOffset, 0);
                        Path malformedPath = output.resolve(tag + "-original-malformed.elf"); Files.write(malformedPath, malformed);
                        try {
                            GhidraUnwindCalls.verify(program, functions.get(0x1000), ElfImage.read(malformedPath), 0, TaskMonitor.DUMMY);
                            throw new AssertionError("unknown original frame source treated as absence");
                        }
                        catch (IllegalArgumentException expected) {
                            require(expected.getMessage().contains("zero length in .debug_frame"), "unrelated malformed-frame rejection");
                        }
                        evidence.append(tag).append(" original-precedence=partial/full/unrelated/malformed/cancellation PASS\n");
                        int[] planPolls = {0};
                        var planCounting = new TaskMonitorAdapter(true) {
                            @Override public void checkCancelled() { planPolls[0]++; }
                        };
                        GhidraUnwindFrames.plan(proof, 0, planCounting);
                        for (int limit = 1; limit <= planPolls[0]; limit++) {
                            int stop = limit; int[] seen = {0};
                            var cancelled = new TaskMonitorAdapter(true) {
                                @Override public void checkCancelled() throws CancelledException {
                                    if (++seen[0] == stop) throw new CancelledException();
                                }
                            };
                            try {
                                GhidraUnwindFrames.plan(proof, 0, cancelled);
                                throw new AssertionError("native frame planning cancellation ignored");
                            }
                            catch (CancelledException expected) { checks++; }
                        }
                        require(GhidraUnwindFrames.plan(proof, 0, TaskMonitor.DUMMY).equals(planned), "native frame planning retry changed rules");
                        evidence.append(tag).append(" frame-planning-polls=").append(planPolls[0]).append('\n');
                        int[] polls = {0};
                        var counting = new TaskMonitorAdapter(true) {
                            @Override public void checkCancelled() { polls[0]++; }
                        };
                        GhidraUnwindCalls.verify(program, functions.get(0x1000), image, 0, counting);
                        for (int limit = 1; limit <= polls[0]; limit++) {
                            int stop = limit; int[] seen = {0};
                            var cancelled = new TaskMonitorAdapter(true) {
                                @Override public void checkCancelled() throws CancelledException {
                                    if (++seen[0] == stop) throw new CancelledException();
                                }
                            };
                            try {
                                GhidraUnwindCalls.verify(program, functions.get(0x1000), image, 0, cancelled);
                                throw new AssertionError("native callee cancellation ignored");
                            }
                            catch (CancelledException expected) { checks++; }
                        }
                        require(GhidraUnwindCalls.verify(program, functions.get(0x1000), image, 0, TaskMonitor.DUMMY)
                            .verified().flows().equals(proof.verified().flows()), "native callee retry changed facts");
                        evidence.append(tag).append(" cancellation-polls=").append(polls[0]).append('\n');
                    }
                }
                catch (IllegalArgumentException rejected) {
                    require(!positive, "positive native callee failed: " + tag + ": " + rejected.getMessage());
                    String expected = switch (shape) {
                        case "clobber" -> "register restoration is unproved";
                        case "unknown-write" -> "store is not proved below entry stack";
                        case "bad-stack" -> "return target or stack restoration is unproved";
                        case "custom" -> "function convention is not the audited ordinary ABI";
                        case "patched" -> "decoded instruction differs from original ELF";
                        default -> "opaque reachable effects";
                    };
                    require(rejected.getMessage().contains(expected), "native counterexample failed for an unrelated reason: " + tag);
                    evidence.append(tag).append(" rejected=").append(rejected.getMessage()).append('\n');
                    var omitted = GhidraUnwindRecovery.recover(program, image, 0, TaskMonitor.DUMMY);
                    require(omitted.plan().isEmpty() && omitted.verifiedFunctions().isEmpty() &&
                        omitted.refusals().size() == source.size(), "refused program produced a partial plan or lost diagnostics");
                }
                for (var item : source.entrySet()) {
                    byte[] expected = HexFormat.of().parseHex(item.getValue()); byte[] actual = new byte[expected.length];
                    if (shape.equals("patched")) expected[arm ? 0 : 1]++;
                    require(program.getMemory().getBytes(language.getDefaultSpace().getAddress(item.getKey()), actual) == actual.length &&
                        Arrays.equals(actual, expected), "native verification changed program bytes");
                }
                require(Arrays.equals(originalImage, image.bytes()), "verification changed the original ELF");
            }
            finally { program.endTransaction(transaction, false); }
        }
        finally { program.release(owner); }
    }

    /** Earlier invalid roots and callers must not suppress unrelated valid leaves. */
    private static void mixed(boolean arm) throws Exception {
        String tag = (arm ? "aarch64" : "x86") + "-mixed-program";
        String leaf = arm ? "c0035fd6" : "c3";
        var source = new LinkedHashMap<Integer, String>();
        source.put(0x1000, (arm ? "200000f9" : "488907") + leaf);
        source.put(0x1100, leaf);
        source.put(0x1200, caller(arm, 0x1200, 0x1100, false));
        source.put(0x1300, caller(arm, 0x1300, 0x1000, false));
        var language = DefaultLanguageService.getLanguageService().getLanguage(
            new LanguageID(arm ? "AARCH64:LE:64:v8A" : "x86:LE:64:default"));
        Object owner = new Object();
        var program = new ProgramDB(tag, language, language.getCompilerSpecByID(new CompilerSpecID(arm ? "default" : "gcc")), owner);
        try {
            int transaction = program.startTransaction("mixed recovery fixture");
            try {
                ElfImage image = image(arm, tag, source);
                byte[] original = image.bytes();
                var empty = GhidraUnwindRecovery.recover(program, image, 0, TaskMonitor.DUMMY);
                require(empty.plan().isEmpty() && empty.refusals().isEmpty(), "empty program inferred a profile or frame");
                // Reverse creation order must not determine collection order.
                for (var item : new java.util.ArrayList<>(source.entrySet()).reversed()) {
                    byte[] bytes = HexFormat.of().parseHex(item.getValue());
                    var entry = language.getDefaultSpace().getAddress(item.getKey());
                    var body = new AddressSet(entry, entry.add(bytes.length - 1));
                    program.getMemory().createInitializedBlock("text" + item.getKey(), entry, bytes.length,
                        (byte) 0, TaskMonitor.DUMMY, false).setExecute(true);
                    program.getMemory().setBytes(entry, bytes);
                    require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY), "decode mixed fixture");
                    program.getFunctionManager().createFunction("mixed_" + item.getKey(), entry, body, SourceType.USER_DEFINED);
                }
                var recovered = GhidraUnwindRecovery.recover(program, image, 0, TaskMonitor.DUMMY);
                require(recovered.verifiedFunctions().stream().map(a -> a.getOffset()).toList().equals(List.of(0x1100L, 0x1200L)),
                    "invalid root suppressed valid independent functions");
                require(recovered.refusals().keySet().stream().map(a -> a.getOffset()).toList().equals(List.of(0x1000L, 0x1300L)) &&
                    recovered.refusals().values().stream().allMatch(s -> s.contains("store is not proved below entry stack")),
                    "invalid caller/callee refusal was lost or changed");
                require(recovered.plan().orElseThrow().frames().stream().map(Frame::address).toList().equals(List.of(0x1100L, 0x1200L)),
                    "shared callee frame was duplicated or output order changed");
                int[] polls = {0};
                var counting = new TaskMonitorAdapter(true) {
                    @Override public void checkCancelled() { polls[0]++; }
                };
                require(GhidraUnwindRecovery.recover(program, image, 0, counting).equals(recovered), "counting changed collected evidence");
                for (int limit = 1; limit <= polls[0]; limit++) {
                    int stop = limit; int[] seen = {0};
                    var cancelled = new TaskMonitorAdapter(true) {
                        @Override public void checkCancelled() throws CancelledException {
                            if (++seen[0] == stop) throw new CancelledException();
                        }
                    };
                    try {
                        GhidraUnwindRecovery.recover(program, image, 0, cancelled);
                        throw new AssertionError("collection returned a partial result after cancellation");
                    }
                    catch (CancelledException expected) { checks++; }
                }
                require(GhidraUnwindRecovery.recover(program, image, 0, TaskMonitor.DUMMY).equals(recovered), "cancellation poisoned retry");
                Path originalPath = output.resolve(tag + ".elf"), saved = output.resolve(tag + ".saved");
                Files.move(originalPath, saved);
                try {
                    GhidraUnwindRecovery.recover(program, image, 0, TaskMonitor.DUMMY);
                    throw new AssertionError("missing original ELF became a per-function omission");
                }
                catch (java.io.IOException expected) { checks++; }
                finally { Files.move(saved, originalPath); }
                require(GhidraUnwindRecovery.recover(program, image, 0, TaskMonitor.DUMMY).equals(recovered), "I/O failure poisoned retry");
                long delta = 0x400000;
                program.setImageBase(program.getImageBase().add(delta), true);
                var rebased = GhidraUnwindRecovery.recover(program, image, delta, TaskMonitor.DUMMY);
                require(rebased.plan().equals(recovered.plan()), "program rebase changed original-image frame rules");
                require(Arrays.equals(original, image.bytes()), "collection changed original ELF bytes");
                evidence.append(tag).append(" collection-polls=").append(polls[0]).append(" result=").append(recovered).append('\n');
            }
            finally { program.endTransaction(transaction, false); }
        }
        finally { program.release(owner); }
    }
}
