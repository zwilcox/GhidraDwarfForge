package ghidradwarfforge.calls;

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;

import com.google.gson.GsonBuilder;
import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.GhidraCallParameters;
import ghidradwarfforge.GhidraParameterAllocation;
import ghidradwarfforge.GhidraTypeGraph;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.unwind.UnwindFlow.Bank;
import ghidradwarfforge.unwind.UnwindFlow.Cell;

/** Independent numerical vectors from real decoded register transfers. */
public final class GhidraCallArgumentFlowSmoke {
    private static int checks;
    private static final List<Object> vectors = new ArrayList<>();
    private static void require(boolean value, String reason) { if (!value) throw new AssertionError(reason); checks++; }
    private static String word(int value) {
        return HexFormat.of().formatHex(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value).array());
    }
    private static String transfer(boolean arm, boolean call, int from, int to) {
        return arm ? word((call ? 0x94000000 : 0x14000000) | (((to - from) >> 2) & 0x03ffffff)) :
            (call ? "e8" : "e9") + word(to - from - 5);
    }
    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])), new HeadlessGhidraApplicationConfiguration());
        Path output = Path.of(args[1]); Files.createDirectories(output);
        for (boolean arm : List.of(false, true)) {
            for (String shape : List.of("incoming", "add-wrap", "constant", "load", "call-kill", "constant-after-call",
                    "join-conflict", "join-agree", "save-reload", "rebase", "micro-select", "unknown-select")) check(arm, shape, output);
        }
        check(false, "narrow-write", output);
        Files.writeString(output.resolve("vectors.json"), new GsonBuilder().create().toJson(vectors) + "\n");
        System.out.println("call-argument-flow-smoke=PASS checks=" + checks + " cases=25 vectors=" + vectors.size());
    }

    private static void check(boolean arm, String shape, Path output) throws Exception {
        String prefix = switch (shape) {
            case "add-wrap", "rebase" -> arm ? "00040011" : "83c701";
            case "constant" -> arm ? "40058052" : "bf2a000000";
            case "load" -> arm ? "200040b9" : "8b38";
            case "join-conflict" -> arm ? "61000034200080520200001440008052" : "85f67407bf01000000eb05bf02000000";
            case "join-agree" -> arm ? "61000034400580520200001440058052" : "85f67407bf2a000000eb05bf2a000000";
            case "save-reload" -> arm ? "e007bfa9e007c1a8" : "575f";
            case "narrow-write" -> "40b7ff";
            case "micro-select", "unknown-select" -> arm ? "3f0000710100010b2010801a" : "89f885f68d3c370f44f8";
            default -> "";
        };
        if (shape.equals("unknown-select")) prefix = (arm ? "410040b9" : "8b30") + prefix;
        boolean calls = shape.equals("call-kill") || shape.equals("constant-after-call");
        if (calls) {
            prefix = arm ? "fd7bbfa9" : "4883ec08";
            prefix += transfer(arm, true, 0x1000 + prefix.length() / 2, 0x2000);
            if (shape.equals("constant-after-call")) prefix += arm ? "40058052" : "bf2a000000";
        }
        int site = prefix.length() / 2;
        String suffix = calls ? (arm ? "fd7bc1a8c0035fd6" : "4883c408c3") : "";
        byte[] code = HexFormat.of().parseHex(prefix + transfer(arm, calls, 0x1000 + site, 0x2000) + suffix);
        byte[] leaf = HexFormat.of().parseHex(arm ? "c0035fd6" : "c3");
        byte[] original = GhidraTailStateProofSmoke.elf(arm, code, leaf);
        Path path = output.resolve((arm ? "arm-" : "x86-") + shape + ".elf"); Files.write(path, original);
        var image = ElfImage.read(path);
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(arm ? "AARCH64:LE:64:v8A" : "x86:LE:64:default"));
        Object owner = new Object();
        var program = new ProgramDB("call-values", language, language.getCompilerSpecByID(new CompilerSpecID(arm ? "default" : "gcc")), owner);
        long delta = shape.equals("rebase") ? 0x400000 : 0;
        try {
            int transaction = program.startTransaction("argument fixture");
            try {
                var entry = language.getDefaultSpace().getAddress(0x1000 + delta);
                var target = language.getDefaultSpace().getAddress(0x2000 + delta);
                program.getMemory().createInitializedBlock("caller", entry, code.length, (byte) 0, TaskMonitor.DUMMY, false).setExecute(true);
                program.getMemory().setBytes(entry, code);
                program.getMemory().createInitializedBlock("callee", target, leaf.length, (byte) 0, TaskMonitor.DUMMY, false).setExecute(true);
                program.getMemory().setBytes(target, leaf);
                var body = new AddressSet(entry, entry.add(code.length - 1));
                var calleeBody = new AddressSet(target, target.add(leaf.length - 1));
                require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY), "caller decode");
                require(new DisassembleCommand(target, calleeBody, true).applyTo(program, TaskMonitor.DUMMY), "callee decode");
                var function = program.getFunctionManager().createFunction("caller", entry, body, SourceType.USER_DEFINED);
                var callee = program.getFunctionManager().createFunction("callee", target, calleeBody, SourceType.USER_DEFINED);
                callee.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true,
                    SourceType.USER_DEFINED, new ParameterImpl("value", IntegerDataType.dataType, program));
                var boundary = GhidraTailStateProof.verify(program, List.of(function), image, delta, TaskMonitor.DUMMY);
                require(boundary.omissions().isEmpty(), "boundary failed: " + shape + " " + boundary.omissions());
                var result = GhidraCallArgumentFlow.analyze(program, boundary, image, delta, TaskMonitor.DUMMY);
                require(result.omissions().isEmpty(), "analysis failed: " + shape + " " + result.omissions());
                require(result.equals(GhidraCallArgumentFlow.analyze(program, boundary, image, delta, TaskMonitor.DUMMY)), "analysis changed on retry");
                var state = result.transfers().get(entry.add(site));
                require(state != null, "missing actual transfer state " + shape);
                var register = program.getRegister(arm ? "w0" : "EDI");
                var value = GhidraCallArgumentFlow.read(state.values(), new Cell(Bank.REGISTER, register.getAddress().getOffset(), 4));
                boolean known = !List.of("load", "call-kill", "join-conflict", "save-reload", "unknown-select").contains(shape);
                require((value != null) == known, "wrong availability: " + shape + " " + value);
                var entries = new ArrayList<GhidraCallParameters.Entry>();
                var registers = TargetRegisterMap.forElf(arm ? "aarch64" : "x86_64", image, () -> false);
                var types = GhidraTypeGraph.extract(program, List.of(new FunctionSymbol("callee", 0x2000, leaf.length)),
                    registers, delta, TaskMonitor.DUMMY, ignored -> { }, java.util.Map.of(), java.util.Map.of(),
                    java.util.Map.of(), GhidraParameterAllocation.UNCHANGED, entries::add);
                require(entries.size() == 1, "missing parameter entry snapshot");
                var binding = GhidraCallParameters.bind(program, callee, types.functions().getFirst(), types.types(),
                    entries, state, registers, image, delta, TaskMonitor.DUMMY);
                require(binding.arguments().size() == (known ? 1 : 0), "incorrect parameter binding: " + shape + " " + binding);
                if (known) {
                    var actual = binding.arguments().getFirst();
                    require(actual.ordinal() == 0 && actual.name().equals("value") && actual.dwarfRegister() == (arm ? 0 : 5) &&
                        actual.value().bytes() == 8, "wrong formal/register identity");
                }
                if (List.of("constant", "constant-after-call", "join-agree").contains(shape)) {
                    require(value instanceof CallValue.Literal literal && literal.value() == 42,
                        "constant incorrectly depends on an incoming register: " + value);
                }
                if (value != null) {
                    for (long input : List.of(0L, 1L, -1L, Long.MIN_VALUE, 0x7fffffffL, 0x80000000L, 0xffffffffL, 0x100000000L)) {
                        long depth = (input & 1) == 0 ? 0 : 3;
                        long expected = switch (shape) {
                            case "add-wrap", "rebase" -> input + 1;
                            case "constant", "constant-after-call", "join-agree" -> 42;
                            case "narrow-write" -> (input & ~0xffL) | 0xff;
                            case "micro-select" -> input + depth;
                            default -> input;
                        };
                        // Remap only the fixture's input register in the independent VM.
                        var row = new LinkedHashMap<String, Object>();
                        row.put("name", (arm ? "arm/" : "x86/") + shape);
                        row.put("addressBytes", 8); row.put("order", "LITTLE_ENDIAN");
                        row.put("registers", java.util.Map.of(arm ? "0" : "5", Long.toUnsignedString(input, 16),
                            arm ? "1" : "4", Long.toHexString(depth)));
                        row.put("expression", HexFormat.of().formatHex(value.dwarf(8, ByteOrder.LITTLE_ENDIAN)));
                        row.put("expected", Long.toHexString(expected & 0xffffffffL)); vectors.add(row);
                        var bound = new LinkedHashMap<>(row);
                        bound.put("name", row.get("name") + "/bound-whole-register");
                        bound.put("expression", HexFormat.of().formatHex(binding.arguments().getFirst().value().dwarf(8, ByteOrder.LITTLE_ENDIAN)));
                        bound.put("expected", Long.toUnsignedString(List.of("incoming", "narrow-write").contains(shape) ? expected : expected & 0xffffffffL, 16));
                        vectors.add(bound);
                    }
                }
                if (shape.equals("incoming")) {
                    require(types.equals(GhidraTypeGraph.extract(program,
                        List.of(new FunctionSymbol("callee", 0x2000, leaf.length)), registers, delta, TaskMonitor.DUMMY,
                        ignored -> { }, java.util.Map.of(), java.util.Map.of(), java.util.Map.of(), GhidraParameterAllocation.UNCHANGED)),
                        "entry observer changed the exported type/storage model");
                    bindingControls(program, callee, state, registers, image, delta, arm);
                    int[] polls = {0};
                    var counting = new TaskMonitorAdapter(true) { @Override public void checkCancelled() { polls[0]++; } };
                    GhidraCallArgumentFlow.analyze(program, boundary, image, delta, counting);
                    for (int index = 1; index <= polls[0]; index++) {
                        int stop = index; int[] count = {0};
                        var cancelled = new TaskMonitorAdapter(true) {
                            @Override public void checkCancelled() throws CancelledException { if (++count[0] == stop) throw new CancelledException(); }
                        };
                        try { GhidraCallArgumentFlow.analyze(program, boundary, image, delta, cancelled); throw new AssertionError("missed cancellation"); }
                        catch (CancelledException expected) { checks++; }
                    }
                }
                require(Arrays.equals(original, Files.readAllBytes(path)), "changed original executable");
            }
            finally { program.endTransaction(transaction, false); }
        }
        finally { program.release(owner); }
    }

    private static void bindingControls(ghidra.program.model.listing.Program program, Function callee,
            GhidraCallArgumentFlow.State state, TargetRegisterMap registers, ElfImage image, long delta, boolean arm)
            throws Exception {
        var enumeration = new ghidra.program.model.data.EnumDataType("Choice", 4);
        enumeration.add("one", 1);
        var scalarTypes = List.of(IntegerDataType.dataType, ghidra.program.model.data.LongLongDataType.dataType,
            new ghidra.program.model.data.TypedefDataType("Count", IntegerDataType.dataType), enumeration,
            new ghidra.program.model.data.PointerDataType(IntegerDataType.dataType, 8),
            ghidra.program.model.data.DoubleDataType.dataType, new ghidra.program.model.data.Undefined4DataType());
        for (var type : scalarTypes) {
            callee.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.USER_DEFINED,
                new ParameterImpl("value", type, program));
            var entries = new ArrayList<GhidraCallParameters.Entry>();
            var types = GhidraTypeGraph.extract(program, List.of(new FunctionSymbol("callee", 0x2000, arm ? 4 : 1)),
                registers, delta, TaskMonitor.DUMMY, ignored -> { }, java.util.Map.of(), java.util.Map.of(),
                java.util.Map.of(), GhidraParameterAllocation.UNCHANGED, entries::add);
            var signature = types.functions().getFirst();
            var binding = GhidraCallParameters.bind(program, callee, signature, types.types(), entries, state,
                registers, image, delta, TaskMonitor.DUMMY);
            boolean expected = scalarTypes.indexOf(type) < 4;
            require(binding.arguments().size() == (expected ? 1 : 0), "type binding guard " + type + " " + binding);
            if (type != IntegerDataType.dataType) continue;
            var low = program.getRegister(arm ? "w0" : "EDI");
            var onlyLow = new GhidraCallArgumentFlow.State(java.util.Map.of(
                new Cell(Bank.REGISTER, low.getAddress().getOffset(), 4), new CallValue.Literal(42, 4)));
            require(GhidraCallParameters.bind(program, callee, signature, types.types(), entries, onlyLow,
                registers, image, delta, TaskMonitor.DUMMY).arguments().isEmpty(), "invented upper register bits");
            require(GhidraCallParameters.bind(program, callee, signature, types.types(), List.of(), state,
                registers, image, delta, TaskMonitor.DUMMY).arguments().isEmpty(), "guessed decompiler-only storage");
            var old = entries.getFirst();
            var changed = new GhidraCallParameters.Entry(old.functionId(), old.function(), old.ordinal(),
                new ghidradwarfforge.types.TypeGraph.Parameter("renamed", old.formal().type(), false),
                old.pieces(), old.assigned(), old.indirect());
            require(GhidraCallParameters.bind(program, callee, signature, types.types(), List.of(changed), state,
                registers, image, delta, TaskMonitor.DUMMY).arguments().isEmpty(), "accepted changed formal identity");
            var indirect = new GhidraCallParameters.Entry(old.functionId(), old.function(), old.ordinal(), old.formal(),
                old.pieces(), true, true);
            require(GhidraCallParameters.bind(program, callee, signature, types.types(), List.of(indirect), state,
                registers, image, delta, TaskMonitor.DUMMY).arguments().isEmpty(), "treated pointer carrier as direct integer");
            var high = new GhidraCallParameters.Entry(old.functionId(), old.function(), old.ordinal(), old.formal(),
                List.of(new GhidraCallParameters.Piece(low.getAddress().add(1), 4)), true, false);
            require(GhidraCallParameters.bind(program, callee, signature, types.types(), List.of(high), state,
                registers, image, delta, TaskMonitor.DUMMY).arguments().isEmpty(), "accepted high register slice as a whole register");
            int[] polls = {0};
            GhidraCallParameters.bind(program, callee, signature, types.types(), entries, state, registers, image, delta,
                new TaskMonitorAdapter(true) { @Override public void checkCancelled() { polls[0]++; } });
            for (int index = 1; index <= polls[0]; index++) {
                final int stop = index; int[] count = {0};
                try {
                    GhidraCallParameters.bind(program, callee, signature, types.types(), entries, state, registers, image, delta,
                        new TaskMonitorAdapter(true) { @Override public void checkCancelled() throws CancelledException {
                            if (++count[0] == stop) throw new CancelledException();
                        } });
                    throw new AssertionError("missed binding cancellation");
                }
                catch (CancelledException expectedCancellation) { checks++; }
            }
        }
        callee.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.USER_DEFINED,
            new ParameterImpl("value", IntegerDataType.dataType, program));
        int[] resolutions = {0};
        var correctedStorage = new ghidra.program.model.listing.VariableStorage(program, program.getRegister(arm ? "w1" : "ESI"));
        GhidraParameterAllocation corrected = (function, monitor, diagnostic) -> {
            resolutions[0]++;
            return java.util.Map.of(0, correctedStorage);
        };
        var entries = new ArrayList<GhidraCallParameters.Entry>();
        var types = GhidraTypeGraph.extract(program, List.of(new FunctionSymbol("callee", 0x2000, arm ? 4 : 1)),
            registers, delta, TaskMonitor.DUMMY, ignored -> { }, java.util.Map.of(), java.util.Map.of(),
            java.util.Map.of(), corrected, entries::add);
        var bound = GhidraCallParameters.bind(program, callee, types.functions().getFirst(), types.types(), entries, state,
            registers, image, delta, TaskMonitor.DUMMY);
        require(resolutions[0] == 1 && bound.arguments().size() == 1 &&
            bound.arguments().getFirst().dwarfRegister() == (arm ? 1 : 4), "allocation correction was recomputed or lost");
        var originalReturn = callee.getReturnType();
        callee.setReturnType(new ghidra.program.model.data.StructureDataType("ReturnObject", 24), SourceType.USER_DEFINED);
        var automatic = java.util.Arrays.stream(callee.getParameters()).filter(p -> p.isAutoParameter()).toList();
        require(automatic.size() == 1, "fixture did not acquire a hidden return carrier");
        GhidraParameterAllocation omitAutomatic = new GhidraParameterAllocation() {
            @Override public java.util.Map<Integer, ghidra.program.model.listing.VariableStorage> corrections(
                    Function function, TaskMonitor monitor, java.util.function.Consumer<String> diagnostic) {
                return java.util.Map.of();
            }
            @Override public Resolution resolve(Function function, TaskMonitor monitor, java.util.function.Consumer<String> diagnostic) {
                return new Resolution(java.util.Map.of(), java.util.Set.of(automatic.getFirst().getOrdinal()));
            }
        };
        entries.clear();
        types = GhidraTypeGraph.extract(program, List.of(new FunctionSymbol("callee", 0x2000, arm ? 4 : 1)),
            registers, delta, TaskMonitor.DUMMY, ignored -> { }, java.util.Map.of(), java.util.Map.of(),
            java.util.Map.of(), omitAutomatic, entries::add);
        bound = GhidraCallParameters.bind(program, callee, types.functions().getFirst(), types.types(), entries, state,
            registers, image, delta, TaskMonitor.DUMMY);
        require(entries.size() == 1 && entries.getFirst().ordinal() == 0 && bound.arguments().size() == 1 &&
            bound.arguments().getFirst().ordinal() == 0 && bound.arguments().getFirst().name().equals("value") &&
            bound.arguments().getFirst().dwarfRegister() == (arm ? 0 : 4), "omitted automatic carrier shifted formal binding");
        callee.setReturnType(originalReturn, SourceType.USER_DEFINED);
    }
}
