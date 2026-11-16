package ghidradwarfforge;

import java.util.Arrays;
import java.util.HexFormat;
import java.util.Map;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.lang.DynamicVariableStorage;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.RegisterStorage;

/** Real saved parameter ownership and explicit carrier rejection, without Program proxies. */
final class StackCarrierOwnershipSmoke {
    private static int checks;

    static int check() throws Exception {
        checks = 0;
        for (boolean x86 : new boolean[] { true, false }) {
            for (int bytes : new int[] { 4, 8 }) {
                check(x86, bytes);
            }
        }
        System.out.println("stack-carrier-ownership-smoke=PASS checks=" + checks);
        return checks;
    }

    private static void check(boolean x86, int bytes) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(
            x86 ? "x86:LE:64:default" : "AARCH64:LE:64:v8A"));
        Object owner = new Object();
        var program = new ProgramDB("carrier-owner", language, language.getDefaultCompilerSpec(), owner);
        var foreign = new ProgramDB("different-program", language, language.getDefaultCompilerSpec(), owner);
        try {
            int tx = program.startTransaction("owned parameter fixtures");
            try {
                var entry = language.getDefaultSpace().getAddress(0x1000);
                byte[] code = HexFormat.of().parseHex(x86 ? "9090c3" : "1f2003d51f2003d5c0035fd6");
                var body = new AddressSet(entry, entry.add(code.length - 1));
                program.getMemory().createInitializedBlock("code", entry, code.length, (byte) 0, TaskMonitor.DUMMY, false).setExecute(true);
                program.getMemory().setBytes(entry, code);
                require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY), "decode owner fixture");
                var function = program.getFunctionManager().createFunction("owner", entry, body, SourceType.USER_DEFINED);
                var other = program.getFunctionManager().createFunction("other", entry.add(0x100),
                    new AddressSet(entry.add(0x100), entry.add(0x100)), SourceType.USER_DEFINED);
                var type = bytes == 4 ? IntegerDataType.dataType : LongLongDataType.dataType;
                String name = x86 ? (bytes == 4 ? "EDI" : "RDI") : (bytes == 4 ? "w0" : "x0");
                var incoming = program.getRegister(name);
                function.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.USER_DEFINED,
                    new ParameterImpl("incoming", type, incoming, program, SourceType.USER_DEFINED));
                var parameter = function.getParameter(0);
                var storage = parameter.getVariableStorage();
                var registers = TargetRegisterMap.forTarget(x86 ? "x86_64" : "aarch64");
                var baseline = StackValueFlow.prove(program, function, parameter, registers, TaskMonitor.DUMMY);
                require(baseline.size() == 1 && baseline.getFirst().start() == entry.getOffset()
                    && baseline.getFirst().end() == entry.getOffset() + code.length
                    && baseline.getFirst().storage() instanceof RegisterStorage register
                    && register.register().dwarfNumber() == (x86 ? 5 : 0) && register.bitSize() == bytes * 8,
                    "complete owned incoming register remains available");
                var detached = new ParameterImpl("incoming", type, incoming, program, SourceType.USER_DEFINED);
                require(StackValueFlow.prove(program, other, parameter, registers, TaskMonitor.DUMMY).isEmpty(),
                    "parameter from another function must not seed a value proof");
                require(StackValueFlow.prove(foreign, function, parameter, registers, TaskMonitor.DUMMY).isEmpty(),
                    "function from another program must not seed a value proof");
                require(StackValueFlow.prove(program, function, detached, registers, TaskMonitor.DUMMY).isEmpty(),
                    "unsaved parameter must not impersonate a saved incoming value");
                require(StackValueFlow.prove(program, function, function.getReturn(), registers, TaskMonitor.DUMMY).isEmpty(),
                    "return value must not be treated as an incoming formal");

                String shortName = x86 ? "DI" : "w1";
                var small = new Varnode(program.getRegister(shortName).getAddress(), bytes / 2);
                var second = new Varnode(program.getRegister(x86 ? "SI" : "w2").getAddress(), bytes / 2);
                var stackPointer = program.getCompilerSpec().getStackPointer();
                VariableStorage[] rejected = { null, VariableStorage.UNASSIGNED_STORAGE, VariableStorage.BAD_STORAGE,
                    VariableStorage.VOID_STORAGE,
                    new VariableStorage(foreign, foreign.getRegister(name)),
                    new VariableStorage(program, small),
                    new VariableStorage(program, small, second),
                    new VariableStorage(program, entry.add(0x800), bytes),
                    new VariableStorage(program, 16, bytes),
                    new VariableStorage(program, new Varnode(stackPointer.getAddress(), bytes)),
                    new DynamicVariableStorage(program, true, storage.getVarnodes()) };
                String[] reasons = { "missing storage", "unassigned storage", "bad storage", "void storage",
                    "foreign program storage", "partial carrier", "split carrier", "memory carrier", "direct stack carrier",
                    "stack pointer as value", "forced-indirect carrier in scalar proof" };
                for (int i = 0; i < rejected.length; i++) {
                    require(StackValueFlow.prove(program, function, parameter, rejected[i], registers, TaskMonitor.DUMMY).isEmpty(),
                        reasons[i] + " must not provide a scalar value location");
                }
                var unmapped = new TargetRegisterMap("missing-incoming", "explicit missing incoming register",
                    Map.of(x86 ? "RAX" : "x1", x86 ? 0 : 1));
                require(StackValueFlow.prove(program, function, parameter, unmapped, TaskMonitor.DUMMY).isEmpty(),
                    "unmapped incoming register must not acquire a DWARF number");
                require(StackValueFlow.proveIndirect(program, function, parameter,
                    new DynamicVariableStorage(program, true, storage.getVarnodes()), registers, TaskMonitor.DUMMY).isEmpty(),
                    "ordinary scalar type must not become a pointer merely from carrier flags");

                var marker = new CancelledException("cancel owned carrier proof");
                var cancelled = new TaskMonitorAdapter(true) {
                    @Override
                    public void checkCancelled() throws CancelledException {
                        throw marker;
                    }
                };
                try {
                    StackValueFlow.prove(program, function, parameter, registers, cancelled);
                    throw new AssertionError("carrier proof ignored cancellation");
                }
                catch (CancelledException expected) {
                    require(expected == marker, "preserve cancellation identity");
                }
                byte[] unchanged = new byte[code.length];
                program.getMemory().getBytes(entry, unchanged);
                require(Arrays.equals(code, unchanged) && function.getParameter(0) == parameter
                    && parameter.getVariableStorage().equals(storage) && parameter.getSource() == SourceType.USER_DEFINED
                    && parameter.getFormalDataType().isEquivalent(type) && function.getBody().equals(body),
                    "rejected carriers and cancellation must preserve original bytes and curated parameter");
                require(StackValueFlow.prove(program, function, parameter, registers, TaskMonitor.DUMMY).equals(baseline),
                    "rejection controls must not poison later owned-value proofs");
            }
            finally {
                program.endTransaction(tx, false);
            }
            require(program.getFunctionManager().getFunctionCount() == 0 && program.getMemory().getBlocks().length == 0,
                "fixture transaction rolls back functions and bytes");
        }
        finally {
            program.flushEvents();
            foreign.flushEvents();
            program.release(owner);
            foreign.release(owner);
        }
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
