package ghidradwarfforge.unwind;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.unwind.UnwindFlow.*;

/** Real Sleigh decode and CFG controls; no exported CFI or ABI-support claim. */
public final class GhidraUnwindInstructionsSmoke {
    // This suite observes raw decoding, including deliberately unsupported opcodes.
    // It makes no ABI/profile acceptance claim; production recovery must supply its guard.
    private static final GhidraUnwindInstructions.InstructionPolicy RAW_DECODER_ONLY = (instruction, monitor) -> monitor.checkCancelled();
    private static int checks;
    private static final StringBuilder evidence = new StringBuilder();

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (boolean conflict : List.of(false, true)) {
            check("x86:LE:64:default", "diamond-" + conflict,
                "85ff74044154eb02" + (conflict ? "4155" : "4154") + "415cc3", 12, !conflict);
            check("AARCH64:LE:64:v8A", "diamond-" + conflict,
                "60000034f37bbfa902000014" + (conflict ? "f47bbfa9" : "f37bbfa9") + "f37bc1a8c0035fd6", 20, !conflict);
        }
        check("x86:LE:64:default", "global-load", "4154488b05f70f0000415cc3", 11, true);
        check("x86:LE:64:default", "global-store", "415449c7c42a000000488905f00f0000415cc3", 18, false);
        check("x86:LE:64:default", "global-rmw", "415449c7c42a00000048ff05f00f0000415cc3", 18, false);
        check("x86:LE:64:default", "global-byte-store", "415449c7c42a0000000f9505f00f0000415cc3", 18, false);
        check("x86:LE:64:default", "save-restore", "41544989fc415cc3", 7, true);
        check("AARCH64:LE:64:v8A", "save-restore", "f37bbfa9130080d2f37bc1a8c0035fd6", 12, true);
        check("x86:LE:64:default", "empty-pcode", "415490415cc3", 5, true);
        check("AARCH64:LE:64:v8A", "empty-pcode", "f37bbfa91f2003d5f37bc1a8c0035fd6", 12, true);
        check("x86:LE:64:default", "shrink-wrap", "85ff74044154415cc3", 8, true);
        check("AARCH64:LE:64:v8A", "shrink-wrap", "80000034f37bbfa9130080d2f37bc1a8c0035fd6", 16, true);
        check("x86:LE:64:default", "discontiguous", "eb0e" + "00".repeat(14) + "4154415cc3", 20, true);
        check("AARCH64:LE:64:v8A", "discontiguous", "04000014" + "00".repeat(12) + "f37bbfa9f37bc1a8c0035fd6", 24, true);
        check("x86:LE:64:default", "opaque", "0f05c3", 2, false);
        // Sleigh models call-next as push plus an intra-function branch. The
        // following pop consumes that PC value; this is not a callee call.
        check("x86:LE:64:default", "get-pc", "e800000000415bc3", 7, true);
        check("x86:LE:64:default", "call", "e8fb0f0000c3", 5, false);
        check("x86:LE:64:default", "call-indirect", "ffd0c3", 2, false);
        check("AARCH64:LE:64:v8A", "call", "00040094c0035fd6", 4, false);
        Path output = Path.of(args[1]);
        Files.createDirectories(output.getParent());
        Files.writeString(output, evidence.toString());
        System.out.println("ghidra-unwind-instructions-smoke=PASS checks=" + checks);
    }

    private static void require(boolean value, String reason) {
        if (!value) throw new AssertionError(reason);
        checks++;
    }
    private static Cell register(ProgramDB program, String name) {
        var register = program.getRegister(name);
        return GhidraUnwindInstructions.cell(new Varnode(register.getAddress(), register.getMinimumByteSize()));
    }

    private static void check(String id, String shape, String hex, int stop, boolean survives) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(id));
        Object owner = new Object();
        var program = new ProgramDB("unwind-effects", language, language.getDefaultCompilerSpec(), owner);
        boolean arm = id.startsWith("AARCH64");
        try {
            int transaction = program.startTransaction("native unwind fixture");
            try {
                byte[] bytes = HexFormat.of().parseHex(hex);
                var entry = language.getDefaultSpace().getAddress(0x1000);
                var end = entry.add(bytes.length - 1);
                var block = program.getMemory().createInitializedBlock("text", entry, bytes.length, (byte) 0, TaskMonitor.DUMMY, false);
                block.setExecute(true);
                program.getMemory().setBytes(entry, bytes);
                var body = new AddressSet(entry, end);
                if (shape.equals("discontiguous")) body.delete(entry.add(arm ? 4 : 2), entry.add(15));
                require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY), "decode " + shape);
                var function = program.getFunctionManager().createFunction("test_frame", entry, body, SourceType.USER_DEFINED);
                var captured = GhidraUnwindInstructions.capture(program, function, RAW_DECODER_ONLY, instruction -> null, TaskMonitor.DUMMY);
                Cell sp = register(program, arm ? "sp" : "RSP");
                Cell saved = register(program, arm ? "x19" : "R12");
                var initial = new LinkedHashMap<Cell, Value>();
                initial.put(sp, new StackAddress(0, 8));
                initial.put(saved, new Incoming(arm ? 19 : 12, 8));
                initial.put(register(program, arm ? "x20" : "R13"), new Incoming(arm ? 20 : 13, 8));
                if (arm) initial.put(register(program, "x30"), new ReturnAddress(8));
                State seed = new State(initial, arm ? Map.of() : Map.of(new Slot(0, 8), new ReturnAddress(8)));
                var result = UnwindFlow.analyze(captured.graph(), entry, seed, sp, () -> false);
                State state = result.before().get(entry.add(stop));
                evidence.append(id).append('/').append(shape).append('\n');
                captured.observations().forEach((address, observation) -> evidence.append(address).append(' ')
                    .append(observation).append("\n  before=").append(result.before().get(address)).append('\n'));
                require(state != null, "unreachable final instruction " + shape);
                require(initial.get(saved).equals(state.values().get(saved)) == survives,
                    "native caller identity mismatch " + id + "/" + shape + " " + state + " " + captured.observations());
                if (!shape.equals("opaque") && !shape.startsWith("call")) {
                    require(state.values().get(sp).equals(new StackAddress(0, 8)), "restore stack relation " + state);
                    if (shape.equals("global-store") || shape.equals("global-byte-store") || shape.equals("global-rmw")) {
                        require(state.memory().isEmpty(), "unproved global/stack alias retained saved memory");
                        require(captured.graph().values().stream().flatMap(node -> node.effects().stream()).anyMatch(effect ->
                            effect instanceof Store store && store.address().equals(new Constant(0x2000, 8)) &&
                            store.bytes() == (shape.equals("global-byte-store") ? 1 : 8)), "direct-memory store lost address or width");
                    }
                    else require(arm ? new ReturnAddress(8).equals(state.values().get(register(program, "x30"))) :
                        new ReturnAddress(8).equals(state.memory().get(new Slot(0, 8))), "caller return identity lost");
                    require(captured.observations().values().stream().allMatch(item -> item.omissions().isEmpty()),
                        "supported fixture has omitted effects");
                    if (shape.startsWith("global-") && !shape.equals("global-load")) {
                        for (var item : captured.graph().entrySet()) {
                            var nativeInstruction = program.getListing().getInstructionAt(item.getKey());
                            long rawEnd = 0;
                            for (var operation : nativeInstruction.getPcode()) {
                                var nodes = new java.util.ArrayList<Varnode>(List.of(operation.getInputs()));
                                if (operation.getOutput() != null) nodes.add(operation.getOutput());
                                for (var node : nodes) if (node.isUnique()) rawEnd = Math.max(rawEnd, node.getOffset() + node.getSize());
                            }
                            for (var effect : item.getValue().effects()) {
                                if (effect instanceof Store store && store.address() instanceof Constant) {
                                    require(store.input() instanceof Cell temporary && temporary.bank() == Bank.TEMPORARY &&
                                        temporary.offset() >= rawEnd, "direct memory output aliases raw instruction temporaries");
                                }
                            }
                        }
                    }
                }
                else require(captured.observations().values().stream().anyMatch(item -> !item.omissions().isEmpty()),
                    "opaque/call proof omission was not recorded");
                int[] polls = {0};
                var counting = new TaskMonitorAdapter(true) {
                    @Override public void checkCancelled() { polls[0]++; }
                };
                GhidraUnwindInstructions.capture(program, function, RAW_DECODER_ONLY, instruction -> null, counting);
                for (int stopPoll = 1; stopPoll <= polls[0]; stopPoll++) {
                    int selected = stopPoll;
                    int[] counter = {0};
                    var cancelled = new TaskMonitorAdapter(true) {
                        @Override public void checkCancelled() throws CancelledException {
                            if (++counter[0] == selected) throw new CancelledException();
                        }
                    };
                    try {
                        GhidraUnwindInstructions.capture(program, function, RAW_DECODER_ONLY, instruction -> null, cancelled);
                        throw new AssertionError("capture ignored cancellation " + selected);
                    }
                    catch (CancelledException expected) { checks++; }
                }
                require(GhidraUnwindInstructions.capture(program, function, RAW_DECODER_ONLY, instruction -> null, TaskMonitor.DUMMY)
                    .equals(captured), "capture retry changed evidence");
                var first = program.getListing().getInstructionAt(entry);
                first.setFlowOverride(FlowOverride.RETURN);
                rejected(() -> GhidraUnwindInstructions.capture(program, function, RAW_DECODER_ONLY, instruction -> null, TaskMonitor.DUMMY));
                first.setFlowOverride(FlowOverride.NONE);
                var partial = new AddressSet(body);
                partial.delete(end, end);
                function.setBody(partial);
                rejected(() -> GhidraUnwindInstructions.capture(program, function, RAW_DECODER_ONLY, instruction -> null, TaskMonitor.DUMMY));
                function.setBody(body);
                program.getListing().clearCodeUnits(entry, entry.add(first.getLength() - 1), false);
                rejected(() -> GhidraUnwindInstructions.capture(program, function, RAW_DECODER_ONLY, instruction -> null, TaskMonitor.DUMMY));
            }
            finally { program.endTransaction(transaction, false); }
        }
        finally { program.release(owner); }
    }
    @FunctionalInterface private interface Checked { void run() throws Exception; }
    private static void rejected(Checked action) throws Exception {
        try { action.run(); throw new AssertionError("incomplete/overridden graph accepted"); }
        catch (IllegalArgumentException expected) { checks++; }
    }
}
