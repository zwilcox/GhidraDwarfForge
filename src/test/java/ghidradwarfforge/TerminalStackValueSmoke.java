package ghidradwarfforge;

import java.io.File;
import java.util.HexFormat;
import java.util.List;
import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.RegisterRelativeStorage;

/** Opaque terminal effects cannot erase proven earlier stack values or escape into callers. */
public final class TerminalStackValueSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (String language : List.of("ARM:LE:32:v8", "ARM:LEBE:32:v8LEInstruction")) {
            for (String shape : List.of("saved", "overwrite", "unknown-store", "middle-opaque", "conditional-return")) {
                check(language, shape);
            }
        }
        System.out.println("terminal-stack-value=PASS checks=" + checks);
    }

    private static void check(String id, String shape) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(id));
        Object owner = new Object();
        var program = new ProgramDB("terminal-stack", language, language.getDefaultCompilerSpec(), owner);
        try {
            int tx = program.startTransaction("source-known body");
            try {
                byte[] bytes = HexFormat.of().parseHex("04b02de500b08de20cd04de208000be5ec3001e3013040e3" +
                    "002093e508301be5033082e00300a0e100d08be204b09de41eff2fe1");
                String replacement = switch (shape) {
                    case "overwrite" -> "08100be5";
                    case "unknown-store" -> "001082e5";
                    case "middle-opaque" -> "000000ef";
                    default -> null;
                };
                if (replacement != null) System.arraycopy(HexFormat.of().parseHex(replacement), 0, bytes, 16, 4);
                if (shape.equals("conditional-return")) bytes[51] = 0x11;
                var entry = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
                var block = program.getMemory().createInitializedBlock("code", entry, 0x1010, (byte) 0,
                    TaskMonitor.DUMMY, false);
                block.setExecute(true);
                program.getMemory().setBytes(entry, bytes);
                var body = new AddressSet(entry, entry.add(bytes.length - 1));
                require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY), "decode");
                var function = program.getFunctionManager().createFunction("scalar", entry, body, SourceType.USER_DEFINED);
                function.setCallingConvention(Function.DEFAULT_CALLING_CONVENTION_STRING);
                function.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true,
                    SourceType.USER_DEFINED, new ParameterImpl("value", UnsignedIntegerDataType.dataType,
                        program, SourceType.USER_DEFINED));
                var map = TargetRegisterMap.forTarget("arm");
                var intervals = StackValueFlow.prove(program, function, function.getParameter(0), map, TaskMonitor.DUMMY);
                if (shape.equals("middle-opaque") || shape.equals("conditional-return")) {
                    require(intervals.isEmpty(), "nonterminal/conditional opacity must reject: " + shape);
                    return;
                }
                require(!intervals.isEmpty(), "missing pre-terminal states: " + id + "/" + shape);
                var handoff = intervals.stream().filter(i -> i.start() <= 0x1028 && i.end() > 0x1028).findFirst().orElseThrow();
                if (shape.equals("saved")) {
                    require(handoff.storage() instanceof RegisterRelativeStorage relative && relative.byteOffset() == 4,
                        "source-known allocated stack copy missing: " + intervals);
                }
                else require(!handoff.storage().available(), "overwritten/unknown slot resurrected: " + shape);
                for (long at : new long[] {0x102c, 0x1030}) {
                    require(!intervals.stream().filter(i -> i.start() <= at && i.end() > at)
                        .findFirst().orElseThrow().storage().available(), "released frame resurrected");
                }
                require(RegisterDefinitionFlow.decodedInstructions(program, function, true, TaskMonitor.DUMMY).isEmpty(),
                    "default effect decoder admitted opaque terminal");
                var terminal = program.getListing().getInstructionAt(entry.add(48));
                terminal.setFlowOverride(FlowOverride.CALL);
                require(StackValueFlow.prove(program, function, function.getParameter(0), map, TaskMonitor.DUMMY).isEmpty(),
                    "overridden terminal admitted");
                terminal.setFlowOverride(FlowOverride.NONE);
                require(StackValueFlow.prove(program, function, function.getParameter(0), map, TaskMonitor.DUMMY).equals(intervals),
                    "restored flow changed result");
                var caller = entry.add(0x1000);
                program.getMemory().setBytes(caller, HexFormat.of().parseHex("fefbffeb1eff2fe1"));
                require(new DisassembleCommand(caller, new AddressSet(caller, caller.add(7)), true)
                    .applyTo(program, TaskMonitor.DUMMY), "decode caller");
                require(DirectLeafCalls.inspect(program,
                    List.of(program.getListing().getInstructionAt(caller)), TaskMonitor.DUMMY) == null,
                    "opaque callee effects escaped into caller");
                var cancelled = new TaskMonitorAdapter(true);
                cancelled.cancel();
                try {
                    StackValueFlow.prove(program, function, function.getParameter(0), map, cancelled);
                    throw new AssertionError("cancellation ignored");
                }
                catch (ghidra.util.exception.CancelledException expected) { checks++; }
            }
            finally { program.endTransaction(tx, true); }
        }
        finally { program.release(owner); }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }
}
