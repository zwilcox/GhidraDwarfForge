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
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.RegisterRelativeStorage;
import ghidradwarfforge.locations.VariableStorageModel.RegisterStorage;
import ghidradwarfforge.locations.VariableStorageModel.Storage;

/** Real stack stores, loads, reuse, aliases and register loss. */
public final class StackValueFlowSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (boolean x86 : new boolean[] { true, false }) {
            for (int bytes : new int[] { 4, 8 }) {
                for (String shape : List.of("reload", "clobbered-slot", "partial-slot", "unknown-store", "other-slot", "lost-register", "respill")) {
                    check(x86, bytes, shape);
                }
            }
        }
        System.out.println("stack-value-flow-smoke=PASS checks=" + checks);
    }

    private static void check(boolean x86, int bytes, String shape) throws Exception {
        String nop = x86 ? "90" : "1f2003d5";
        String allocate = x86 ? "4883ec20" : "ff8300d1";
        String store = x86 ? (bytes == 4 ? "897c2408" : "48897c2408") : (bytes == 4 ? "e00b00b9" : "e00700f9");
        String killOriginal = x86 ? "31ff" : "e0031faa";
        String load = x86 ? (bytes == 4 ? "448b542408" : "4c8b542408") : (bytes == 4 ? "e90b40b9" : "e90740f9");
        String overwrite = x86 ? "c644240a00" : "ff2b0039";
        String unknownStore = x86 ? "c60600" : "3f000039";
        String otherStore = x86 ? "c644241800" : "ff630039";
        String killLoaded = x86 ? "4531d2" : "e9031f2a";
        String release = x86 ? "4883c420" : "ff830091";
        var code = new StringBuilder(allocate);
        int saved = code.length() / 2;
        code.append(store).append(nop);
        int kill = code.length() / 2;
        code.append(killOriginal);
        int handoff = code.length() / 2;
        code.append(nop);
        int destructive = -1;
        if (shape.equals("clobbered-slot") || shape.equals("partial-slot")) {
            destructive = code.length() / 2;
            code.append(shape.equals("clobbered-slot")
                ? (x86 ? (bytes == 4 ? "c744240800000000" : "48c744240800000000") :
                    (bytes == 4 ? "ff0b00b9" : "ff0700f9")) : overwrite).append(nop);
        }
        if (shape.equals("unknown-store")) {
            destructive = code.length() / 2;
            code.append(unknownStore).append(nop);
        }
        if (shape.equals("other-slot")) code.append(otherStore).append(nop);
        int reload = code.length() / 2;
        code.append(load);
        int ready = code.length() / 2;
        code.append(nop);
        // Retire the memory source after the load. The register still holds
        // the incoming value, while any later load of the slot is unproven.
        int reused = code.length() / 2;
        code.append(overwrite).append(nop);
        int killed = -1;
        int restored = -1;
        if (shape.equals("lost-register") || shape.equals("respill")) {
            if (shape.equals("respill")) {
                code.append(x86 ? (bytes == 4 ? "4489542410" : "4c89542410") : (bytes == 4 ? "e91300b9" : "e90b00f9"));
            }
            code.append(killLoaded);
            killed = code.length() / 2;
            code.append(nop);
            if (shape.equals("respill")) {
                code.append(x86 ? (bytes == 4 ? "448b5c2410" : "4c8b5c2410") : (bytes == 4 ? "ea1340b9" : "ea0b40f9"));
                restored = code.length() / 2;
                code.append(nop);
            }
        }
        code.append(release);
        int returned = code.length() / 2;
        code.append(x86 ? "c3" : "c0035fd6");
        byte[] machine = HexFormat.of().parseHex(code.toString());
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(
            x86 ? "x86:LE:64:default" : "AARCH64:LE:64:v8A"));
        Object owner = new Object();
        var program = new ProgramDB("stack-value", language, language.getDefaultCompilerSpec(), owner);
        try {
            int tx = program.startTransaction("stack transfers");
            try {
                var entry = language.getDefaultSpace().getAddress(0x1000);
                var body = new AddressSet(entry, entry.add(machine.length - 1));
                var block = program.getMemory().createInitializedBlock("code", entry, machine.length, (byte) 0, TaskMonitor.DUMMY, false);
                block.setExecute(true);
                program.getMemory().setBytes(entry, machine);
                require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY), "decode");
                var function = program.getFunctionManager().createFunction("transfer", entry, body, SourceType.USER_DEFINED);
                var type = bytes == 4 ? IntegerDataType.dataType : LongLongDataType.dataType;
                function.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.USER_DEFINED,
                    new ParameterImpl("value", type, program.getRegister(x86 ? (bytes == 4 ? "EDI" : "RDI") : (bytes == 4 ? "w0" : "x0")), program, SourceType.USER_DEFINED));
                var parameter = function.getParameter(0);
                var map = TargetRegisterMap.forTarget(x86 ? "x86_64" : "aarch64");
                var intervals = StackValueFlow.prove(program, function, parameter, map, TaskMonitor.DUMMY);
                String context = (x86 ? "x86" : "arm") + "/" + bytes + "/" + shape + " " + intervals;
                boolean lostBeforeReload = shape.equals("clobbered-slot") || shape.equals("partial-slot") || shape.equals("unknown-store");
                if (lostBeforeReload) {
                    require(intervals.isEmpty(), "unproven overwritten reload: " + context);
                }
                else {
                    require(!intervals.isEmpty(), "no stack transition proof: " + context);
                    require(at(intervals, 0) instanceof RegisterStorage, "incoming register");
                    require(at(intervals, saved) instanceof RegisterStorage, "store has not completed");
                    require(at(intervals, kill) instanceof RegisterStorage, "original pre-kill");
                    require(at(intervals, handoff) instanceof RegisterRelativeStorage relative && relative.byteOffset() == 8,
                        "completed spill handoff: " + context);
                    require(at(intervals, reload) instanceof RegisterRelativeStorage, "load pre-state");
                    require(at(intervals, ready) instanceof RegisterStorage register && register.register().dwarfNumber() == (x86 ? 10 : 9),
                        "completed load: " + context);
                    require(at(intervals, reused) instanceof RegisterStorage, "slot reuse must preserve register: " + context);
                    if (shape.equals("lost-register")) {
                        require(!at(intervals, killed).available() && !at(intervals, returned).available(), "lost value cannot reappear: " + context);
                    }
                    else {
                        if (shape.equals("respill")) {
                            require(at(intervals, killed) instanceof RegisterRelativeStorage relative && relative.byteOffset() == 16, "second spill: " + context);
                            require(at(intervals, restored) instanceof RegisterStorage register && register.register().dwarfNumber() == (x86 ? 11 : 10), "second reload: " + context);
                        }
                        require(at(intervals, returned) instanceof RegisterStorage, "register survives released frame: " + context);
                    }
                }
                var rejected = GhidraVariableStorage.stableParameter(program, function, parameter, map, TaskMonitor.DUMMY);
                var publicRanges = GhidraVariableStorage.parameterPrefix(program, function, parameter, map, rejected, TaskMonitor.DUMMY);
                if (!lostBeforeReload && !shape.equals("lost-register")) {
                    require(at(publicRanges, returned) instanceof RegisterStorage, "public proof missed surviving register: " + publicRanges);
                }
                if (shape.equals("lost-register")) require(!at(publicRanges, returned).available(), "public proof resurrected lost value");
                var loadInstruction = program.getListing().getInstructionAt(entry.add(reload));
                loadInstruction.setFlowOverride(ghidra.program.model.listing.FlowOverride.RETURN);
                require(StackValueFlow.prove(program, function, parameter, map, TaskMonitor.DUMMY).isEmpty(), "flow override admitted");
                loadInstruction.setFlowOverride(ghidra.program.model.listing.FlowOverride.NONE);
                var reference = program.getReferenceManager().addMemoryReference(entry.add(0x1000), entry.add(ready),
                    ghidra.program.model.symbol.RefType.UNCONDITIONAL_JUMP, SourceType.USER_DEFINED, 0);
                require(StackValueFlow.prove(program, function, parameter, map, TaskMonitor.DUMMY).isEmpty(), "outside entry admitted");
                program.getReferenceManager().delete(reference);
                require(StackValueFlow.prove(program, function, parameter, map, TaskMonitor.DUMMY).equals(intervals), "guard controls changed proof");
                var cancelled = new TaskMonitorAdapter(true);cancelled.cancel();
                try {
                    StackValueFlow.prove(program, function, parameter, map, cancelled);
                    throw new AssertionError("cancel ignored");
                }
                catch (ghidra.util.exception.CancelledException expected) { checks++; }
            }
            finally { program.endTransaction(tx, true); }
        }
        finally { program.release(owner); }
    }

    private static Storage at(List<GhidraVariableStorage.StorageInterval> intervals, long offset) {
        return intervals.stream().filter(i -> i.start() <= 0x1000 + offset && i.end() > 0x1000 + offset).findFirst().orElseThrow().storage();
    }
    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
