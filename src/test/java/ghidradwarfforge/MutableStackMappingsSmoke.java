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

/** Saved stack identity, recorded assignments and stale physical backup rejection. */
public final class MutableStackMappingsSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (boolean x86 : new boolean[] { true, false }) {
            for (int bytes : new int[] { 4, 8 }) {
                for (String shape : List.of("saved", "unsaved", "unknown", "partial", "other-owner", "offcut")) {
                    check(x86, bytes, shape);
                }
            }
        }
        System.out.println("mutable-stack-mappings-smoke=PASS checks=" + checks);
    }

    private static void check(boolean x86, int bytes, String shape) throws Exception {
        String nop = x86 ? "90" : "1f2003d5";
        String allocate = x86 ? "4883ec20" : "ff8300d1";
        String store = x86 ? (bytes == 4 ? "897c2408" : "48897c2408") : (bytes == 4 ? "e00b00b9" : "e00700f9");
        String load = x86 ? (bytes == 4 ? "448b542408" : "4c8b542408") : (bytes == 4 ? "e90b40b9" : "e90740f9");
        String update = x86 ? (bytes == 4 ? "4183c205" : "4983c205") : (bytes == 4 ? "29150011" : "29150091");
        String save = x86 ? (bytes == 4 ? "4489542408" : "4c89542408") : (bytes == 4 ? "e90b00b9" : "e90700f9");
        String kill = x86 ? "4531d2" : "e9031f2a";
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
        int assignment = code.length() / 2;
        code.append(update);
        int updated = code.length() / 2;
        code.append(nop);
        int saving = code.length() / 2;
        code.append(shape.equals("unsaved") ? nop : save).append(nop);
        int killing = code.length() / 2;
        code.append(kill);
        int killed = code.length() / 2;
        code.append(nop).append(load);
        int reloaded = code.length() / 2;
        code.append(nop);
        int losing = code.length() / 2;
        code.append(shape.equals("partial") ? (x86 ? "c644240a00" : "ff2b0039") :
            shape.equals("unknown") ? (x86 ? "c60600" : "3f000039") : store);
        int lost = code.length() / 2;
        code.append(nop).append(load);
        int staleReload = code.length() / 2;
        code.append(nop).append(release).append(x86 ? "c3" : "c0035fd6");
        byte[] machine = HexFormat.of().parseHex(code.toString());
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(
            x86 ? "x86:LE:64:default" : "AARCH64:LE:64:v8A"));
        Object owner = new Object();
        var program = new ProgramDB("mutable-stack-mappings", language, language.getDefaultCompilerSpec(), owner);
        String context = (x86 ? "x86" : "arm") + "/" + bytes + "/" + shape;
        try {
            int tx = program.startTransaction("explicit stack mapping");
            try {
                var entry = language.getDefaultSpace().getAddress(0x1000);
                var body = new AddressSet(entry, entry.add(machine.length - 1));
                var block = program.getMemory().createInitializedBlock("code", entry, machine.length, (byte) 0, TaskMonitor.DUMMY, false);
                block.setExecute(true);
                program.getMemory().setBytes(entry, machine);
                require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY), "decode " + context);
                var function = program.getFunctionManager().createFunction("fixture", entry, body, SourceType.USER_DEFINED);
                var type = bytes == 4 ? IntegerDataType.dataType : LongLongDataType.dataType;
                var register = program.getRegister(x86 ? (bytes == 4 ? "R10D" : "R10") : (bytes == 4 ? "w9" : "x9"));
                var stack = (LocalVariable) function.addLocalVariable(new LocalVariableImpl("value", type, -24,
                    program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
                stack.setFirstUseOffset(definition);
                function.addLocalVariable(new LocalVariableImpl("value$1", loading, type, register,
                    program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
                function.addLocalVariable(new LocalVariableImpl("value$2", assignment + (shape.equals("offcut") ? 1 : 0),
                    type, register, program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
                if (shape.equals("other-owner")) {
                    var other = (LocalVariable) function.addLocalVariable(new LocalVariableImpl("other", type, -24,
                        program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
                    other.setFirstUseOffset(losing);
                }
                var diagnostics = new ArrayList<String>();
                var groups = GhidraLocalMappings.extract(program, function, TaskMonitor.DUMMY, diagnostics::add);
                require(groups.size() == 1, "saved identity " + context + diagnostics);
                var group = groups.getFirst();
                var registers = TargetRegisterMap.forTarget(x86 ? "x86_64" : "aarch64");
                var proof = MergedLocalLifetime.prove(program, function, group, registers, TaskMonitor.DUMMY);
                boolean negative = shape.equals("offcut") || shape.equals("other-owner");
                if (negative) require(proof.isEmpty(), "unproved mapping must be omitted " + context);
                else {
                    require(!proof.isEmpty(), "expected proof " + context);
                    require(!at(proof, definition).available(), "before initialization " + context);
                    require(at(proof, initialized) instanceof RegisterRelativeStorage, "initialized stack " + context);
                    require(at(proof, loaded) instanceof RegisterStorage, "loaded mapping " + context);
                    require(at(proof, updated) instanceof RegisterStorage, "new assigned value " + context);
                    require(at(proof, saving) instanceof RegisterStorage, "old slot must be stale " + context);
                    require(at(proof, killed).available() == !shape.equals("unsaved"), "saved update survives register loss " + context);
                    if (!shape.equals("unsaved")) {
                        require(at(proof, killed) instanceof RegisterRelativeStorage, "saved current slot " + context);
                        require(at(proof, reloaded) instanceof RegisterStorage, "reload current logical value " + context);
                    }
                    else require(!at(proof, reloaded).available(), "old physical slot must not resurrect previous value " + context);
                    require(!at(proof, lost).available() && !at(proof, staleReload).available(), "unknown new owner/write retires all copies " + context);
                }
                var model = GhidraTypeGraph.extract(program, List.of(new FunctionSymbol("fixture", 0x1000, machine.length)),
                    x86 ? "x86_64" : "aarch64", 0, TaskMonitor.DUMMY, diagnostics::add);
                require(model.functions().getFirst().locals().stream().filter(local -> local.name().startsWith("value")).count() == 1,
                    "one canonical declaration " + context);
                var variable = model.variableStorage().variables().stream().filter(value -> value.name().equals("value")).findFirst().orElseThrow();
                require(variable.locations().stream().anyMatch(range -> range.storage().available()) == !negative,
                    "public exporter uses the same proof " + context);
                var cancelled = new TaskMonitorAdapter(true);
                cancelled.cancel();
                try {
                    MergedLocalLifetime.prove(program, function, group, registers, cancelled);
                    throw new AssertionError("cancel lost");
                }
                catch (CancelledException expected) { checks++; }
            }
            finally { program.endTransaction(tx, true); }
        }
        finally { program.release(owner); }
    }

    private static Storage at(List<GhidraVariableStorage.StorageInterval> proof, int offset) {
        return proof.stream().filter(interval -> interval.start() <= 0x1000L + offset && interval.end() > 0x1000L + offset)
            .findFirst().orElseThrow().storage();
    }

    private static void require(boolean value, String message) {
        checks++;
        if (!value) throw new AssertionError(message);
    }
}
