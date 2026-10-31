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
import ghidra.program.model.listing.LocalVariable;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.RegisterRelativeStorage;
import ghidradwarfforge.locations.VariableStorageModel.RegisterStorage;
import ghidradwarfforge.locations.VariableStorageModel.Storage;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;

/** Real instruction boundaries for curated stack definitions, reloads and reuse. */
public final class StackLocalLifetimeSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (boolean x86 : new boolean[] { true, false }) {
            for (int bytes : new int[] { 4, 8 }) {
                for (String shape : List.of("reuse", "partial", "unknown", "other-slot", "released",
                        "bad-start", "read-start", "analysis", "zero-owner", "same-start")) {
                    check(x86, bytes, shape);
                }
            }
        }
        System.out.println("stack-local-lifetime-smoke=PASS checks=" + checks);
    }

    private static void check(boolean x86, int bytes, String shape) throws Exception {
        String nop = x86 ? "90" : "1f2003d5";
        String allocate = x86 ? "4883ec20" : "ff8300d1";
        String store = x86 ? (bytes == 4 ? "897c2408" : "48897c2408") : (bytes == 4 ? "e00b00b9" : "e00700f9");
        String load = x86 ? (bytes == 4 ? "448b542408" : "4c8b542408") : (bytes == 4 ? "e90b40b9" : "e90740f9");
        String overwrite = x86 ? "c644240a00" : "ff2b0039";
        String unknown = x86 ? "c60600" : "3f000039";
        String other = x86 ? "c644241800" : "ff630039";
        String release = x86 ? "4883c420" : "ff830091";
        var code = new StringBuilder(allocate).append(nop);
        int definition = code.length() / 2;
        code.append(store);
        int initialized = code.length() / 2;
        code.append(nop);
        int loading = code.length() / 2;
        code.append(load);
        int loaded = code.length() / 2;
        code.append(nop);
        int reuse = code.length() / 2;
        code.append(shape.equals("partial") ? overwrite : shape.equals("unknown") ? unknown :
            shape.equals("other-slot") ? other : shape.equals("released") ? release : store);
        int retired = code.length() / 2;
        code.append(nop).append(load);
        int reloaded = code.length() / 2;
        code.append(nop);
        if (!shape.equals("released")) code.append(release);
        int returned = code.length() / 2;
        code.append(x86 ? "c3" : "c0035fd6");
        byte[] machine = HexFormat.of().parseHex(code.toString());
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(
            x86 ? "x86:LE:64:default" : "AARCH64:LE:64:v8A"));
        Object owner = new Object();
        var program = new ProgramDB("stack-local-lifetime", language, language.getDefaultCompilerSpec(), owner);
        String description = (x86 ? "x86" : "arm") + "/" + bytes + "/" + shape;
        try {
            int tx = program.startTransaction("stack local definitions");
            try {
                var entry = language.getDefaultSpace().getAddress(0x1000);
                var body = new AddressSet(entry, entry.add(machine.length - 1));
                var block = program.getMemory().createInitializedBlock("code", entry, machine.length,
                    (byte) 0, TaskMonitor.DUMMY, false);
                block.setExecute(true);
                program.getMemory().setBytes(entry, machine);
                require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY), "decode");
                var function = program.getFunctionManager().createFunction("fixture", entry, body, SourceType.USER_DEFINED);
                var type = bytes == 4 ? IntegerDataType.dataType : LongLongDataType.dataType;
                var first = (LocalVariable) function.addLocalVariable(new LocalVariableImpl("first", type,
                    -24, program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
                first.setFirstUseOffset(shape.equals("bad-start") ? definition + 1 :
                    shape.equals("read-start") ? loading : definition);
                if (shape.equals("analysis")) first.getSymbol().setSource(SourceType.ANALYSIS);
                LocalVariable second = null;
                if (shape.equals("reuse") || shape.equals("same-start") || shape.equals("zero-owner")) {
                    second = (LocalVariable) function.addLocalVariable(new LocalVariableImpl("second", type,
                        -24, program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
                    second.setFirstUseOffset(shape.equals("same-start") ? definition : shape.equals("zero-owner") ? 0 : reuse);
                    require(function.getLocalVariables().length == 2, "two owners retained");
                }
                var registers = TargetRegisterMap.forTarget(x86 ? "x86_64" : "aarch64");
                Storage rejected = GhidraVariableStorage.stableLocal(program, function, first, registers, TaskMonitor.DUMMY);
                var proof = StackLocalLifetime.prove(program, function, first, registers, rejected, TaskMonitor.DUMMY);
                boolean negative = List.of("bad-start", "read-start", "analysis", "same-start").contains(shape);
                if (negative) require(proof.isEmpty(), description + " must not guess a definition");
                else {
                    require(!proof.isEmpty(), description + " expected proof");
                    for (int offset : new int[] { 0, definition }) {
                        require(!at(proof, entry.getOffset() + offset).available(), description + " stale bytes before definition");
                    }
                    require(at(proof, entry.getOffset() + initialized) instanceof RegisterRelativeStorage,
                        description + " completed STORE in exact slot");
                    require(at(proof, entry.getOffset() + loaded) instanceof RegisterStorage,
                        description + " completed LOAD establishes register copy");
                    require(at(proof, entry.getOffset() + retired).available() == shape.equals("other-slot"),
                        description + " old register must not survive local assignment/reuse");
                    require(at(proof, entry.getOffset() + reloaded).available() == shape.equals("other-slot"),
                        description + " retired slot must not reestablish old identity");
                    require(!at(proof, entry.getOffset() + returned).available(), description + " released frame ends local");
                    if (shape.equals("reuse")) {
                        require(!at(proof, entry.getOffset() + reuse).available(), "next owner retires before its instruction");
                    }
                }
                var model = GhidraTypeGraph.extract(program, List.of(new FunctionSymbol("fixture", entry.getOffset(),
                    machine.length)), x86 ? "x86_64" : "aarch64", 0, TaskMonitor.DUMMY, message -> { });
                var firstModel = model.variableStorage().variables().stream().filter(value -> value.name().equals("first"))
                    .findFirst().orElseThrow();
                require(firstModel.locations().stream().anyMatch(value -> value.storage().available()) == !negative,
                    description + " production extraction must use the same proof");
                if (second != null) {
                    Storage secondRejected = GhidraVariableStorage.stableLocal(program, function, second, registers, TaskMonitor.DUMMY);
                    require(!secondRejected.available(), description + " overlapping owner cannot have a whole-function location");
                    var secondProof = StackLocalLifetime.prove(program, function, second, registers, secondRejected, TaskMonitor.DUMMY);
                    if (shape.equals("reuse")) {
                        require(!at(secondProof, entry.getOffset() + reuse).available(), "second local not initialized before STORE");
                        require(at(secondProof, entry.getOffset() + retired) instanceof RegisterRelativeStorage, "new owner starts after STORE");
                        require(at(secondProof, entry.getOffset() + reloaded) instanceof RegisterStorage, "new owner migrates after LOAD");
                    }
                    else require(secondProof.isEmpty(), "ambiguous or zero owner must not infer initialization");
                }
                var cancelled = new TaskMonitorAdapter(true);
                cancelled.cancel();
                try {
                    StackLocalLifetime.prove(program, function, first, registers, rejected, cancelled);
                    throw new AssertionError("cancellation lost");
                }
                catch (CancelledException expected) { checks++; }
            }
            finally { program.endTransaction(tx, true); }
        }
        finally { program.release(owner); }
    }

    private static Storage at(List<GhidraVariableStorage.StorageInterval> proof, long pc) {
        return proof.stream().filter(interval -> interval.start() <= pc && interval.end() > pc)
            .findFirst().orElseThrow(() -> new AssertionError("missing instruction interval " + pc)).storage();
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
