package ghidradwarfforge;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
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
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariable;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.RegisterRelativeStorage;
import ghidradwarfforge.locations.VariableStorageModel.RegisterStorage;
import ghidradwarfforge.locations.VariableStorageModel.Storage;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;

/** Actual machine CFGs, including losing backedges and different carriers at joins. */
public final class StackControlFlowSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (boolean x86 : new boolean[] { true, false }) {
            for (int bytes : new int[] { 4, 8 }) {
                for (boolean local : new boolean[] { true, false }) {
                    for (String shape : List.of("diamond", "diamond-kill", "bypass", "loop", "loop-kill",
                            "redefine", "reuse", "split", "undecoded", "stack-drift")) {
                        if (!local && (shape.equals("redefine") || shape.equals("reuse"))) continue;
                        check(x86, bytes, local, shape);
                    }
                }
            }
        }
        System.out.println("stack-control-flow-smoke=PASS checks=" + checks);
    }

    private static void check(boolean x86, int bytes, boolean local, String shape) throws Exception {
        var code = new Code(x86);
        String nop = x86 ? "90" : "1f2003d5";
        String allocate = x86 ? "4883ec20" : "ff8300d1";
        String release = x86 ? "4883c420" : "ff830091";
        String store = x86 ? (bytes == 4 ? "897c2408" : "48897c2408") : (bytes == 4 ? "e00b00b9" : "e00700f9");
        String load = x86 ? (bytes == 4 ? "448b542408" : "4c8b542408") : (bytes == 4 ? "e90b40b9" : "e90740f9");
        String alternate = x86 ? (bytes == 4 ? "448b5c2408" : "4c8b5c2408") : (bytes == 4 ? "ea0b40b9" : "ea0740f9");
        String partial = x86 ? "c644240a00" : "ff2b0039";
        String kill = x86 ? "31ff" : "e0031faa";
        String compare = x86 ? "85f6" : "3f000071";
        String decrement = x86 ? "83ee01" : "21040071";
        code.emit(allocate + nop);
        if (shape.equals("bypass")) { code.emit(compare); code.branch("merge", 0); }
        code.label("definition"); code.emit(store);
        code.label("ready"); code.emit(nop);
        code.label("merge");
        if (!shape.equals("redefine")) code.emit(kill);
        if (shape.startsWith("diamond")) {
            code.emit(compare); code.branch("right", 0);
            code.emit(load);
            if (shape.equals("diamond-kill")) code.emit(partial);
            code.branch("join", -1);
            code.label("right"); code.emit(alternate);
        }
        else if (shape.equals("split") || shape.equals("undecoded")) {
            code.branch("join", -1);
            code.label("hole"); code.emit(x86 ? "cccccc" : "000020d4");
        }
        else if (shape.startsWith("loop") || shape.equals("stack-drift")) {
            code.label("loop"); code.emit(nop);
            if (shape.equals("stack-drift")) code.emit(x86 ? "4883ec10" : "ff4300d1");
            code.emit(load);
            if (shape.equals("loop-kill")) code.emit(partial);
            code.emit(decrement); code.branch("loop", 1);
        }
        else if (shape.equals("redefine") || shape.equals("reuse")) {
            code.emit(load);
            code.label("otherOwner"); code.emit(nop);
            code.emit(decrement); code.branch("definition", 1);
        }
        code.label("join"); code.emit(nop + load);
        code.label("loaded"); code.emit(nop + release);
        code.label("returned"); code.emit(x86 ? "c3" : "c0035fd6");
        byte[] machine = code.bytes();
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(
            x86 ? "x86:LE:64:default" : "AARCH64:LE:64:v8A"));
        Object owner = new Object();
        var program = new ProgramDB("stack-flow", language, language.getDefaultCompilerSpec(), owner);
        String context = (x86 ? "x86" : "arm") + "/" + bytes + "/local=" + local + "/" + shape;
        try {
            int tx = program.startTransaction("machine flow");
            try {
                var entry = language.getDefaultSpace().getAddress(0x1000);
                var body = new AddressSet(entry, entry.add(machine.length - 1));
                if (shape.equals("split")) body.delete(entry.add(code.at("hole")), entry.add(code.at("join") - 1));
                var block = program.getMemory().createInitializedBlock("code", entry, machine.length, (byte) 0, TaskMonitor.DUMMY, false);
                block.setExecute(true); program.getMemory().setBytes(entry, machine);
                require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY), "decode " + context);
                var function = program.getFunctionManager().createFunction("fixture", entry, body, SourceType.USER_DEFINED);
                var type = bytes == 4 ? IntegerDataType.dataType : LongLongDataType.dataType;
                Variable variable;
                if (local) {
                    var declared = (LocalVariable) function.addLocalVariable(new LocalVariableImpl("value", type, -24,
                        program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
                    declared.setFirstUseOffset(code.at("definition")); variable = declared;
                    if (shape.equals("reuse")) {
                        var other = (LocalVariable) function.addLocalVariable(new LocalVariableImpl("other", type, -24,
                            program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
                        other.setFirstUseOffset(code.at("otherOwner"));
                    }
                }
                else {
                    function.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.USER_DEFINED,
                        new ParameterImpl("value", type, program.getRegister(x86 ? (bytes == 4 ? "EDI" : "RDI") :
                            (bytes == 4 ? "w0" : "x0")), program, SourceType.USER_DEFINED));
                    variable = function.getParameter(0);
                }
                var registers = TargetRegisterMap.forTarget(x86 ? "x86_64" : "aarch64");
                var rejected = local ? GhidraVariableStorage.stableLocal(program, function, variable, registers, TaskMonitor.DUMMY) : null;
                var intervals = local ? StackLocalLifetime.prove(program, function, variable, registers, rejected, TaskMonitor.DUMMY) :
                    StackValueFlow.prove(program, function, function.getParameter(0), registers, TaskMonitor.DUMMY);
                if (shape.equals("undecoded")) {
                    require(intervals.isEmpty(), "included undecoded gap " + context); return;
                }
                require(!intervals.isEmpty(), "no proof " + context);
                boolean joined = List.of("diamond", "loop", "redefine", "split").contains(shape);
                require(at(intervals, code.at("join")).available() == joined, "join agreement " + context + intervals);
                require(at(intervals, code.at("loaded")).available() == joined, "reload agreement " + context + intervals);
                require(at(intervals, code.at("ready")) instanceof RegisterRelativeStorage || !local,
                    "local definition must discard prior register copies " + context);
                if (shape.equals("diamond")) require(at(intervals, code.at("join")) instanceof RegisterRelativeStorage,
                    "join cannot choose one branch register " + context);
                if (shape.equals("loop-kill") || shape.equals("stack-drift")) require(!at(intervals, code.at("loop")).available(),
                    "loop backedge must lose first-visit-only fact " + context);
                if (shape.equals("reuse")) require(!at(intervals, code.at("otherOwner")).available(), "owner retires before read " + context);
                if (local) require(!at(intervals, code.at("returned")).available(), "released local " + context);
                for (var interval : intervals) require(body.contains(entry.getAddressSpace().getAddress(interval.start()),
                    entry.getAddressSpace().getAddress(interval.end() - 1)), "crossed body hole " + context);
                var ranges = new ArrayList<FunctionRange>();
                for (var range : body) ranges.add(new FunctionRange(range.getMinAddress().getOffset(), range.getLength()));
                var model = GhidraTypeGraph.extract(program, List.of(new FunctionSymbol("fixture", 0x1000, ranges)),
                    x86 ? "x86_64" : "aarch64", 0, TaskMonitor.DUMMY, message -> { });
                var actual = model.variableStorage().variables().stream().filter(value -> value.name().equals("value")).findFirst().orElseThrow();
                long join = 0x1000 + code.at("join");
                require(actual.locations().stream().anyMatch(range -> range.start() <= join && join < range.end() && range.storage().available()) == joined,
                    "production extraction bypassed CFG proof " + context + actual);
                var reference = program.getReferenceManager().addMemoryReference(entry.subtract(16), entry.add(code.at("join")),
                    RefType.UNCONDITIONAL_JUMP, SourceType.USER_DEFINED, 0);
                require((local ? StackLocalLifetime.prove(program, function, variable, registers, rejected, TaskMonitor.DUMMY) :
                    StackValueFlow.prove(program, function, function.getParameter(0), registers, TaskMonitor.DUMMY)).isEmpty(), "outside entry " + context);
                program.getReferenceManager().delete(reference);
                var cancelled = new TaskMonitorAdapter(true); cancelled.cancel();
                try {
                    if (local) StackLocalLifetime.prove(program, function, variable, registers, rejected, cancelled);
                    else StackValueFlow.prove(program, function, function.getParameter(0), registers, cancelled);
                    throw new AssertionError("cancellation lost");
                }
                catch (CancelledException expected) { checks++; }
            }
            finally { program.endTransaction(tx, true); }
        }
        finally { program.release(owner); }
    }

    private static Storage at(List<GhidraVariableStorage.StorageInterval> intervals, int offset) {
        long address = 0x1000 + offset;
        return intervals.stream().filter(value -> value.start() <= address && address < value.end()).findFirst().orElseThrow().storage();
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }

    private static final class Code {
        private record Branch(int start, String target, int condition) { }
        private final boolean x86;
        private final ByteArrayOutputStream output = new ByteArrayOutputStream();
        private final Map<String, Integer> labels = new LinkedHashMap<>();
        private final List<Branch> branches = new ArrayList<>();
        Code(boolean x86) { this.x86 = x86; }
        void emit(String hex) { output.writeBytes(HexFormat.of().parseHex(hex)); }
        void label(String name) { if (labels.put(name, output.size()) != null) throw new AssertionError(name); }
        int at(String name) { return labels.get(name); }
        void branch(String target, int condition) {
            branches.add(new Branch(output.size(), target, condition));
            emit(x86 ? (condition < 0 ? "e900000000" : condition == 0 ? "0f8400000000" : "0f8500000000") : "00000000");
        }
        byte[] bytes() {
            byte[] result = output.toByteArray();
            var buffer = ByteBuffer.wrap(result).order(ByteOrder.LITTLE_ENDIAN);
            for (var branch : branches) {
                int delta = at(branch.target()) - branch.start();
                if (x86) {
                    int length = branch.condition() < 0 ? 5 : 6;
                    buffer.putInt(branch.start() + length - 4, delta - length);
                }
                else {
                    if (delta % 4 != 0) throw new AssertionError("unaligned branch");
                    buffer.putInt(branch.start(), branch.condition() < 0 ? 0x14000000 | ((delta >> 2) & 0x3ffffff) :
                        0x54000000 | (((delta >> 2) & 0x7ffff) << 5) | branch.condition());
                }
            }
            return result;
        }
    }
}
