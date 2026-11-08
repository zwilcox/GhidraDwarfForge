package ghidradwarfforge.unwind;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;

import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.unwind.CallFramePlan.*;

/** Test-only native byte/range importer exercising mandatory original-byte agreement. */
public final class UnwindFrameRecoveryProbe {
    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        ElfImage image = ElfImage.read(Path.of(args[1]));
        boolean arm = image.machine() == 183;
        if (!arm && image.machine() != 62) throw new IllegalArgumentException("unsupported probe target");
        long rebase = Long.decode(args[4]);
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(arm ? "AARCH64:LE:64:v8A" : "x86:LE:64:default"));
        Object owner = new Object();
        var program = new ProgramDB("recovered-frame-probe", language,
            language.getCompilerSpecByID(new CompilerSpecID(arm ? "default" : "gcc")), owner);
        try {
            int transaction = program.startTransaction("original fixture bytes");
            try {
                var functions = new LinkedHashMap<String, Function>();
                var records = Files.readAllLines(Path.of(args[2]));
                for (String line : records) {
                    String[] fields = line.split(" ");
                    byte[] bytes = HexFormat.of().parseHex(fields[2]);
                    var address = language.getDefaultSpace().getAddress(Long.parseUnsignedLong(fields[1], 16));
                    program.getMemory().createInitializedBlock(fields[0], address, bytes.length,
                        (byte) 0, TaskMonitor.DUMMY, false).setExecute(true);
                    program.getMemory().setBytes(address, bytes);
                }
                for (String line : records) {
                    String[] fields = line.split(" ");
                    var entry = language.getDefaultSpace().getAddress(Long.parseUnsignedLong(fields[1], 16));
                    var body = new AddressSet(entry, entry.add(fields[2].length() / 2 - 1));
                    if (!new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY)) {
                        throw new AssertionError("fixture decoding failed");
                    }
                    functions.put(fields[0], program.getFunctionManager().createFunction(fields[0], entry, body, SourceType.USER_DEFINED));
                }
                if (rebase != 0) program.setImageBase(program.getImageBase().add(rebase), true);
                if (args.length > 6 && Boolean.parseBoolean(args[6])) {
                    var observations = new StringBuilder();
                    for (var function : functions.values()) {
                        if (function.getName().equals("_start")) continue;
                        var profile = ghidradwarfforge.targets.UnwindAbiProfile.select(program, function, image, rebase, TaskMonitor.DUMMY);
                        var captured = GhidraUnwindInstructions.capture(program, function, profile::requireInstruction,
                            instruction -> new UnwindFlow.Call(java.util.Set.copyOf(profile.calleeSavedCells()),
                                profile.description().returnStackAdjustment(), 0L, "diagnostic hypothesis only"), TaskMonitor.DUMMY);
                        var flow = UnwindFlow.analyze(captured.graph(), function.getEntryPoint(), profile.entry(), profile.stackPointer(), () -> false,
                            (instruction, index, effect, before) -> {
                                if (effect instanceof UnwindFlow.Store store) {
                                    var address = store.address() instanceof UnwindFlow.Constant constant ? constant :
                                        before.values().get((UnwindFlow.Cell) store.address());
                                    String resolved = address instanceof UnwindFlow.Constant constant ? "absolute:" + Long.toHexString(constant.value()) :
                                        address instanceof UnwindFlow.StackAddress stack ? "stack:" + stack.offset() : "unknown";
                                    observations.append("MEMORY_WRITE ").append(function.getName()).append(' ').append(instruction)
                                        .append(' ').append(resolved).append(' ').append(store.bytes()).append('\n');
                                    observations.append("STORE ").append(function.getName()).append(' ').append(instruction)
                                        .append(' ').append(effect).append(" before=").append(before).append('\n');
                                }
                            });
                        observations.append(function.getName()).append(" captured=").append(captured).append(" flow=").append(flow).append('\n');
                    }
                    Files.writeString(Path.of(args[3] + ".inspection.txt"), observations.toString());
                }
                String expectedFailure = args.length > 7 ? args[7] : "";
                var separation = UnwindStackSeparation.NONE;
                if (args.length > 8 && !args[8].isEmpty()) {
                    String[] range = args[8].split(":");
                    if (range.length != 2) throw new IllegalArgumentException("expected an explicit address range");
                    separation = new UnwindStackSeparation(8, List.of(new UnwindStackSeparation.Region(
                        Long.parseUnsignedLong(range[0], 16), Long.parseUnsignedLong(range[1], 16))),
                        "test-only assumption: supplied absolute range never aliases any live stack in this call group or its callers");
                }
                GhidraUnwindCalls.Evidence evidence;
                try {
                    evidence = GhidraUnwindCalls.verify(program, functions.get(args.length > 5 ? args[5] : "cf_recurse"), image, rebase, TaskMonitor.DUMMY, separation);
                }
                catch (IllegalArgumentException failure) {
                    if (!expectedFailure.isEmpty() && failure.getMessage().equals(expectedFailure)) {
                        Files.writeString(Path.of(args[3] + ".refusal.txt"), failure.getMessage() + "\n");
                        System.out.println("recovered-frame-negative=PASS " + failure.getMessage());
                        return;
                    }
                    throw failure;
                }
                if (!expectedFailure.isEmpty()) throw new AssertionError("unproved fixture unexpectedly qualified");
                if (separation.conditional()) {
                    if (!evidence.verified().separation().equals(separation)) throw new AssertionError("native verification lost its condition");
                    for (var flow : evidence.verified().flows().values()) {
                        if (!flow.separation().equals(separation)) throw new AssertionError("native flow lost its condition");
                    }
                    for (var entry : evidence.verified().bodies().keySet()) {
                        if (!evidence.verified().summary(entry).separation().equals(separation)) {
                            throw new AssertionError("native call summary lost its condition");
                        }
                    }
                    try {
                        GhidraUnwindFrames.plan(evidence, rebase, TaskMonitor.DUMMY);
                        throw new AssertionError("unqualified projection accepted conditional proof");
                    }
                    catch (IllegalArgumentException expected) {
                        if (!expected.getMessage().equals("conditional stack separation requires an explicit qualified projection path")) throw expected;
                    }
                    Files.writeString(Path.of(args[3] + ".condition.txt"), separation + "\nfunctions=" +
                        evidence.verified().bodies().keySet() + "\nflows=" + evidence.verified().flows() + "\n");
                    System.out.println("conditional-native-proof=PASS functions=" + evidence.verified().bodies().size());
                    return;
                }
                var planned = GhidraUnwindFrames.plan(evidence, rebase, TaskMonitor.DUMMY);
                if (planned.observations().stream().anyMatch(row -> !row.projection().covered())) throw new AssertionError("fixture has omitted rows");
                var recovered = GhidraUnwindRecovery.recover(program, image, rebase, TaskMonitor.DUMMY);
                var expectedRefusals = functions.containsKey("_start") ?
                    java.util.Set.of(functions.get("_start").getEntryPoint()) : java.util.Set.<ghidra.program.model.address.Address>of();
                if (!recovered.refusals().keySet().equals(expectedRefusals) ||
                        recovered.refusals().values().stream().anyMatch(reason ->
                            !reason.equals("ELF process entry is not an ordinary called frame") && !reason.contains("opaque reachable effects")) ||
                        !recovered.plan().orElseThrow().equals(planned.plan()) ||
                        !recovered.originalBytes().equals(evidence.originalBytes())) {
                    throw new AssertionError("program collection differs from the independently verified call group");
                }
                writePlan(Path.of(args[3]), recovered.plan().orElseThrow());
                var observations = new StringBuilder();
                evidence.captures().forEach((function, captured) -> observations.append(function).append(' ').append(captured).append('\n'));
                planned.observations().forEach(row -> observations.append(row).append('\n'));
                var matches = new StringBuilder();
                evidence.originalBytes().forEach((address, match) -> matches.append(Long.toHexString(match.address()))
                    .append(' ').append(Long.toHexString(match.fileOffset())).append(' ').append(match.bytes())
                    .append(' ').append(match.sha256()).append('\n'));
                Files.writeString(Path.of(args[3] + ".original-bytes.txt"), matches.toString());
                Files.writeString(Path.of(args[3] + ".evidence.txt"), observations.toString());
                Files.writeString(Path.of(args[3] + ".program.txt"), recovered.toString() + "\n");
                System.out.println("recovered-frame-plan=PASS frames=" + planned.plan().frames().size() + " instructions=" + planned.observations().size());
            }
            finally { program.endTransaction(transaction, false); }
        }
        finally { program.release(owner); }
    }
    private static String rule(Rule rule) {
        return switch (rule) {
            case Undefined ignored -> "u";
            case SameValue ignored -> "s";
            case AtCfaOffset at -> "m:" + at.offset();
            case CfaValue value -> "v:" + value.offset();
            case InRegister register -> "r:" + register.register();
        };
    }
    private static String rules(java.util.Map<Integer, Rule> rules) {
        return String.join(",", rules.entrySet().stream().map(item -> item.getKey() + ":" + rule(item.getValue())).toList());
    }
    private static void writePlan(Path path, CallFramePlan plan) throws Exception {
        var out = new StringBuilder(plan.addressBytes() + " little " + plan.returnRegister() + " " +
            String.join(",", plan.registers().stream().map(String::valueOf).toList()) + "\n");
        out.append("initial ").append(rules(plan.initialRules())).append('\n');
        for (Frame frame : plan.frames()) {
            out.append("frame ").append(Long.toUnsignedString(frame.address(), 16)).append(' ')
                .append(Long.toHexString(frame.size())).append('\n');
            for (Row row : frame.rows()) out.append("row ").append(Long.toUnsignedString(row.address(), 16)).append(' ')
                .append(row.cfa().register()).append(' ').append(row.cfa().offset()).append(' ').append(rules(row.rules())).append('\n');
        }
        Files.writeString(path, out.toString());
    }
}
