package ghidradwarfforge;

import java.io.File;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
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
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.GhidraVariableStorage.StorageInterval;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.CompositeStorage;
import ghidradwarfforge.locations.VariableStorageModel.RegisterRelativeStorage;
import ghidradwarfforge.locations.VariableStorageModel.RegisterStorage;
import ghidradwarfforge.locations.VariableStorageModel.Storage;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;

/** Actual decoded independent piece transfers; no detached scalar parameters. */
public final class CompositeValueFlowSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (boolean x86 : new boolean[] { true, false }) {
            for (int bytes : new int[] { 4, 8 }) {
                for (boolean mixed : new boolean[] { false, true }) {
                    for (String shape : List.of("reload", "partial", "unknown", "other", "lost-second", "second-backup", "late-load", "released-slot")) {
                        check(x86, bytes, mixed, shape);
                    }
                }
            }
        }
        for (boolean bigEndian : new boolean[] { true, false }) {
            for (boolean mixed : new boolean[] { true, false }) armOrder(bigEndian, mixed);
        }
        System.out.println("composite-value-flow-smoke=PASS checks=" + checks);
    }

    private static void check(boolean x86, int bytes, boolean mixed, String shape) throws Exception {
        String nop = x86 ? "90" : "1f2003d5";
        String allocate = x86 ? "4883ec20" : "ff8300d1";
        String store = x86 ? (bytes == 4 ? "897c2408" : "48897c2408") : (bytes == 4 ? "e00b00b9" : "e00700f9");
        String kill = x86 ? "31ff" : "e0031faa";
        String load = x86 ? (bytes == 4 ? "448b542408" : "4c8b542408") : (bytes == 4 ? "e90b40b9" : "e90740f9");
        String partial = x86 ? "c644240a00" : "ff2b0039";
        String killLoaded = x86 ? "4531d2" : "e9031f2a";
        var code = new StringBuilder();
        if (mixed && !shape.equals("late-load")) code.append(x86 ? (bytes == 4 ? "8b742408" : "488b742408") :
            (bytes == 4 ? "e11340b9" : "e10b40f9"));
        int stackLoaded = code.length() / 2;
        code.append(allocate);
        if (mixed && shape.equals("late-load")) code.append(x86 ? (bytes == 4 ? "8b742428" : "488b742428") :
            (bytes == 4 ? "e13340b9" : "e11b40f9"));
        if (shape.equals("late-load")) stackLoaded = code.length() / 2;
        code.append(store).append(kill);
        int spilled = code.length() / 2;
        code.append(nop);
        if (shape.equals("partial")) code.append(partial);
        if (shape.equals("unknown")) code.append(x86 ? "c60200" : "5f000039");
        if (shape.equals("other")) code.append(x86 ? "c644241800" : "ff630039");
        if (shape.equals("lost-second") && mixed) code.append(x86 ? "c644242800" : "ffc30039");
        if (shape.equals("lost-second") || shape.equals("second-backup")) code.append(x86 ? "31f6" : "e1031faa");
        if (shape.equals("released-slot")) code.append(x86 ? "4883c4204883ec20" : "ff830091ff8300d1");
        code.append(load);
        int reloaded = code.length() / 2;
        code.append(nop).append(partial).append(nop).append(killLoaded);
        int lost = code.length() / 2;
        code.append(nop).append(load);
        int stale = code.length() / 2;
        code.append(nop).append(x86 ? "4883c420c3" : "ff830091c0035fd6");
        byte[] machine = HexFormat.of().parseHex(code.toString());
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(
            x86 ? "x86:LE:64:default" : "AARCH64:LE:64:v8A"));
        Object owner = new Object();
        var program = new ProgramDB("composite-value", language, language.getDefaultCompilerSpec(), owner);
        try {
            int transaction = program.startTransaction("independent pieces");
            try {
                var start = language.getDefaultSpace().getAddress(0x1000);
                var body = new AddressSet(start, start.add(machine.length - 1));
                var block = program.getMemory().createInitializedBlock("code", start, machine.length,
                    (byte) 0, TaskMonitor.DUMMY, false);
                block.setExecute(true);
                program.getMemory().setBytes(start, machine);
                require(new DisassembleCommand(start, body, true).applyTo(program, TaskMonitor.DUMMY), "decode");
                Function function = program.getFunctionManager().createFunction("pieces", start, body, SourceType.USER_DEFINED);
                var type = new StructureDataType("Pair", 0, program.getDataTypeManager());
                type.add(bytes == 4 ? IntegerDataType.dataType : LongLongDataType.dataType, "first", null);
                type.add(bytes == 4 ? IntegerDataType.dataType : LongLongDataType.dataType, "second", null);
                var first = program.getRegister(x86 ? (bytes == 4 ? "EDI" : "RDI") : (bytes == 4 ? "w0" : "x0"));
                var second = program.getRegister(x86 ? (bytes == 4 ? "ESI" : "RSI") : (bytes == 4 ? "w1" : "x1"));
                var storage = new VariableStorage(program,
                    mixed ? new Varnode(program.getAddressFactory().getStackSpace().getAddress(x86 ? 8 : 16), bytes) :
                        new Varnode(second.getAddress(), bytes), new Varnode(first.getAddress(), bytes));
                function.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.USER_DEFINED,
                    new ParameterImpl("pair", type, storage, program, SourceType.USER_DEFINED));
                Parameter parameter = function.getParameter(0);
                var map = TargetRegisterMap.forTarget(x86 ? "x86_64" : "aarch64");
                var intervals = CompositeValueFlow.prove(program, function, parameter, map, TaskMonitor.DUMMY);
                String context = (x86 ? "x86" : "arm") + "/" + bytes + "/" + mixed + "/" + shape + " " + intervals;
                var incoming = composite(at(intervals, 0), context);
                require(incoming.totalBitSize() == bytes * 16L && incoming.pieces().size() == 2, "exact size: " + context);
                require(incoming.pieces().get(0).storage() instanceof RegisterStorage register &&
                    register.register().dwarfNumber() == (x86 ? 5 : 0), "memory order: " + context);
                require(mixed == (incoming.pieces().get(1).storage() instanceof RegisterRelativeStorage), "incoming carrier: " + context);
                require(composite(at(intervals, stackLoaded), context).pieces().get(1).storage() instanceof RegisterStorage,
                    "completed incoming stack load: " + context);
                require(composite(at(intervals, spilled), context).pieces().get(0).storage() instanceof RegisterRelativeStorage relative &&
                    relative.byteOffset() == 8, "first piece spill: " + context);
                boolean valid = shape.equals("reload") || shape.equals("other") || shape.equals("late-load") || (mixed && shape.equals("second-backup"));
                require(at(intervals, reloaded).available() == valid, "all pieces required: " + context);
                if (valid) require(composite(at(intervals, reloaded), context).pieces().get(0).storage() instanceof RegisterStorage register &&
                    register.register().dwarfNumber() == (x86 ? 10 : 9), "piece reload: " + context);
                require(!at(intervals, lost).available() && !at(intervals, stale).available(), "lost piece/stale bytes: " + context);
                var model = GhidraTypeGraph.extract(program, List.of(new FunctionSymbol("pieces", 0x1000,
                    body.getNumAddresses())), x86 ? "x86_64" : "aarch64", 0, TaskMonitor.DUMMY, ignored -> { });
                var modeled = model.variableStorage().variables().stream().filter(value -> value.name().equals("pair"))
                    .findFirst().orElseThrow().locations().stream()
                    .map(row -> new StorageInterval(row.start(), row.end(), row.storage())).toList();
                require(at(modeled, spilled).equals(at(intervals, spilled)) &&
                    at(modeled, reloaded).available() == valid && !at(modeled, stale).available(),
                    "public extraction lost the proven composite transitions: " + modeled);
                Parameter detached = (Parameter) Proxy.newProxyInstance(Parameter.class.getClassLoader(),
                    new Class<?>[] { Parameter.class }, (proxy, method, arguments) -> method.invoke(parameter, arguments));
                require(CompositeValueFlow.prove(program, function, detached, map, TaskMonitor.DUMMY).isEmpty(), "detached identity accepted");
                var cancelled = new TaskMonitorAdapter(true);
                cancelled.cancel();
                try {
                    CompositeValueFlow.prove(program, function, parameter, map, cancelled);
                    throw new AssertionError("ignored cancellation");
                }
                catch (CancelledException expected) { checks++; }
                program.getListing().clearCodeUnits(start, start, false);
                require(CompositeValueFlow.prove(program, function, parameter, map, TaskMonitor.DUMMY).isEmpty(), "undecoded prefix accepted");
            }
            finally { program.endTransaction(transaction, false); }
        }
        finally { program.release(owner); }
    }

    private static void armOrder(boolean bigEndian, boolean mixed) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(
            bigEndian ? "ARM:BE:32:v8" : "ARM:LE:32:v8"));
        Object owner = new Object();
        var program = new ProgramDB("piece-byte-order", language, language.getDefaultCompilerSpec(), owner);
        try {
            int transaction = program.startTransaction("memory ordered pieces");
            try {
                String encoded = (mixed ? "e59d1000" : "") + "e1a04000e3a00000e1a05001e3a01000e3a04000eafffffe";
                byte[] code = HexFormat.of().parseHex(encoded);
                if (!bigEndian) for (int index = 0; index < code.length; index += 4) {
                    byte first = code[index], second = code[index + 1];
                    code[index] = code[index + 3]; code[index + 1] = code[index + 2];
                    code[index + 2] = second; code[index + 3] = first;
                }
                var start = language.getDefaultSpace().getAddress(0x1000);
                var body = new AddressSet(start, start.add(code.length - 1));
                var block = program.getMemory().createInitializedBlock("code", start, code.length,
                    (byte) 0, TaskMonitor.DUMMY, false);
                block.setExecute(true);
                program.getMemory().setBytes(start, code);
                program.getProgramContext().setValue(program.getRegister("TMode"), start,
                    body.getMaxAddress(), BigInteger.ZERO);
                require(new DisassembleCommand(start, body, true).applyTo(program, TaskMonitor.DUMMY), "ARM decode");
                var function = program.getFunctionManager().createFunction("ordered", start, body, SourceType.USER_DEFINED);
                var type = new StructureDataType("OrderedPair", 0, program.getDataTypeManager());
                type.add(IntegerDataType.dataType, "first", null);
                type.add(IntegerDataType.dataType, "second", null);
                var first = new Varnode(program.getRegister("r0").getAddress(), 4);
                var second = new Varnode(mixed ? program.getAddressFactory().getStackSpace().getAddress(0) :
                    program.getRegister("r1").getAddress(), 4);
                var storage = new VariableStorage(program, bigEndian ? first : second, bigEndian ? second : first);
                function.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.USER_DEFINED,
                    new ParameterImpl("pair", type, storage, program, SourceType.USER_DEFINED));
                var intervals = CompositeValueFlow.prove(program, function, function.getParameter(0),
                    TargetRegisterMap.forTarget("arm"), TaskMonitor.DUMMY);
                if (intervals.isEmpty()) {
                    System.out.println("empty ARM proof bigEndian=" + bigEndian + " mixed=" + mixed + " storage=" + storage);
                    System.out.println("decoded=" + RegisterDefinitionFlow.decodedInstructions(program, function, true, TaskMonitor.DUMMY).size());
                    for (var instruction : program.getListing().getInstructions(body, true)) {
                        System.out.println(instruction.getAddress() + " " + instruction);
                    }
                }
                int prefix = mixed ? 4 : 0;
                var moved = composite(at(intervals, prefix + 16), "ARM order " + bigEndian + "/" + mixed);
                require(moved.pieces().size() == 2 && moved.totalBitSize() == 64 &&
                    moved.pieces().get(0).storage() instanceof RegisterStorage low && low.register().dwarfNumber() == 4 &&
                    moved.pieces().get(1).storage() instanceof RegisterStorage high && high.register().dwarfNumber() == 5,
                    "Ghidra significance order must become DWARF memory order: " + moved);
                require(!at(intervals, prefix + 20).available(), "retained half cannot stand for whole object");
            }
            finally { program.endTransaction(transaction, false); }
        }
        finally { program.release(owner); }
    }

    private static CompositeStorage composite(Storage storage, String context) {
        require(storage instanceof CompositeStorage, "missing complete composite: " + context);
        return (CompositeStorage) storage;
    }

    private static Storage at(List<StorageInterval> intervals, int offset) {
        return intervals.stream().filter(row -> row.start() <= 0x1000 + offset && row.end() > 0x1000 + offset)
            .findFirst().orElseThrow(() -> new AssertionError("missing address " + offset + ": " + intervals)).storage();
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }
}
