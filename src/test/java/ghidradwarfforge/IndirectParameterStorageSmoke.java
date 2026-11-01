package ghidradwarfforge;

import java.io.File;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.IndirectMemoryStorage;
import ghidradwarfforge.locations.VariableStorageModel.RegisterRelativeStorage;
import ghidradwarfforge.locations.VariableStorageModel.Storage;

/** Real dynamic ABI pointers, spill/reload boundaries and failed carrier proofs. */
public final class IndirectParameterStorageSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (String shape : List.of("spill", "partial-slot", "incoming-stack", "incoming-overwrite")) {
            check(shape);
        }
        System.out.println("indirect-parameter-storage-smoke=PASS checks=" + checks);
    }

    private static void check(String shape) throws Exception {
        boolean incomingStack = shape.startsWith("incoming-");
        boolean overwrite = shape.endsWith("overwrite") || shape.equals("partial-slot");
        // Incoming stack pointer: optional byte overwrite, then load x9 and return.
        // Register pointer: allocate, spill x0, kill x0, optional overlapping byte write,
        // reload x9, release. All observations are before the instruction executes.
        String code = incomingStack
            ? (overwrite ? "ff030039" : "1f2003d5") + "e90340f91f2003d5c0035fd6"
            : "ff8300d1e00700f9e0031faa" + (overwrite ? "ff2b0039" : "1f2003d5") +
                "e90740f91f2003d5ff830091c0035fd6";
        byte[] machine = HexFormat.of().parseHex(code);
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("AARCH64:LE:64:v8A"));
        Object owner = new Object();
        var program = new ProgramDB("indirect-" + shape, language, language.getDefaultCompilerSpec(), owner);
        try {
            int transaction = program.startTransaction("fixture");
            try {
                var entry = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
                var body = new AddressSet(entry, entry.add(machine.length - 1));
                var block = program.getMemory().createInitializedBlock("code", entry, machine.length,
                    (byte) 0, TaskMonitor.DUMMY, false);
                block.setExecute(true);
                program.getMemory().setBytes(entry, machine);
                require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY), "decode");
                var function = program.getFunctionManager().createFunction("indirect", entry, body, SourceType.USER_DEFINED);
                var aggregate = new StructureDataType("Large", 0, program.getDataTypeManager());
                for (String name : List.of("first", "second", "third")) aggregate.add(LongLongDataType.dataType, name, null);
                var parameters = new ArrayList<Parameter>();
                if (incomingStack) {
                    for (int index = 0; index < 8; index++) parameters.add(new ParameterImpl("word" + index,
                        LongLongDataType.dataType, program, SourceType.USER_DEFINED));
                }
                parameters.add(new ParameterImpl("value", aggregate, program, SourceType.USER_DEFINED));
                function.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true,
                    SourceType.USER_DEFINED, parameters.toArray(Parameter[]::new));
                var parameter = function.getParameter(incomingStack ? 8 : 0);
                require(parameter.getVariableStorage().isForcedIndirect() && parameter.getLength() == 8 &&
                    parameter.getFormalDataType().getLength() == 24, "fixture lacks a genuine ABI pointer");
                var registers = TargetRegisterMap.forTarget("aarch64");
                var intervals = StackValueFlow.proveIndirect(program, function, parameter, registers, TaskMonitor.DUMMY);
                if (incomingStack) {
                    require(at(intervals, 0) instanceof IndirectMemoryStorage memory &&
                        memory.pointerLocation() instanceof RegisterRelativeStorage relative &&
                        relative.register().dwarfNumber() == 31 && relative.byteOffset() == 0,
                        "incoming pointer slot is not the formal object's bytes: " + intervals);
                    require(overwrite ? !at(intervals, 8).available() :
                        at(intervals, 8) instanceof RegisterRelativeStorage relative &&
                            relative.register().dwarfNumber() == 9 && relative.byteOffset() == 0,
                        "incoming slot load boundary: " + intervals);
                }
                else {
                    require(at(intervals, 0) instanceof RegisterRelativeStorage relative &&
                        relative.register().dwarfNumber() == 0 && relative.byteOffset() == 0, "register pointer entry");
                    require(at(intervals, 12) instanceof IndirectMemoryStorage memory &&
                        memory.pointerLocation() instanceof RegisterRelativeStorage relative && relative.byteOffset() == 8,
                        "pointer spill must add a dereference: " + intervals);
                    require(overwrite ? !at(intervals, 20).available() :
                        at(intervals, 20) instanceof RegisterRelativeStorage relative && relative.register().dwarfNumber() == 9,
                        "pointer reload or partial overwrite: " + intervals);
                }
                require(StackValueFlow.prove(program, function, parameter, registers, TaskMonitor.DUMMY).isEmpty(),
                    "ordinary scalar proof must not admit forced indirection");
                var reference = program.getReferenceManager().addMemoryReference(entry.add(0x1000), entry.add(8),
                    ghidra.program.model.symbol.RefType.UNCONDITIONAL_JUMP, SourceType.USER_DEFINED, 0);
                require(StackValueFlow.proveIndirect(program, function, parameter, registers, TaskMonitor.DUMMY).isEmpty(),
                    "external entry must invalidate carrier proof");
                program.getReferenceManager().delete(reference);
                require(intervals.equals(StackValueFlow.proveIndirect(program, function, parameter, registers, TaskMonitor.DUMMY)),
                    "proof changed after negative control");
                var cancelled = new TaskMonitorAdapter(true);
                cancelled.cancel();
                try {
                    StackValueFlow.proveIndirect(program, function, parameter, registers, cancelled);
                    throw new AssertionError("cancellation ignored");
                }
                catch (ghidra.util.exception.CancelledException expected) { checks++; }
            }
            finally { program.endTransaction(transaction, true); }
        }
        finally { program.release(owner); }
    }

    private static Storage at(List<GhidraVariableStorage.StorageInterval> intervals, int offset) {
        return intervals.stream().filter(i -> i.start() <= 0x1000 + offset && i.end() > 0x1000 + offset)
            .findFirst().orElseThrow().storage();
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
