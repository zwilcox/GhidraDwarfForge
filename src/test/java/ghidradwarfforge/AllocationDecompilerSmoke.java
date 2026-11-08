package ghidradwarfforge;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import ghidra.GhidraApplicationLayout;
import ghidra.app.decompiler.DecompInterface;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.pcodeCPort.opcodes.OpCode;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import static ghidra.program.model.pcode.AttributeId.*;
import static ghidra.program.model.pcode.ElementId.*;

/** Lossless typed transport and analyst metadata preservation with the actual Ghidra model. */
public final class AllocationDecompilerSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
        Object owner = new Object();
        var program = new ProgramDB("source-view", language,
            language.getCompilerSpecByID(new CompilerSpecID("gcc")), owner);
        try {
            transport(program);
            bounds();
            int tx = program.startTransaction("model");
            try { preservation(program); }
            finally { program.endTransaction(tx, true); }
        }
        finally { program.release(owner); }
        System.out.println("allocation-decompiler-smoke=PASS checks=" + checks);
    }

    private static void transport(Program program) throws Exception {
        var tree = new GhidraEncoderTree(TaskMonitor.DUMMY);
        var expected = new ArrayList<String>();
        var actual = new ArrayList<String>();
        writeAll(recorder(expected, null), program);
        writeAll(tree, program);
        for (var root : tree.roots()) root.replay(recorder(actual, null), TaskMonitor.DUMMY);
        require(actual.equals(expected), "wire method, type, signedness or argument changed");
        var monitor = new TaskMonitorAdapter(true);
        rejects(() -> tree.roots().get(0).replay(recorder(new ArrayList<>(), monitor), monitor), "cancelled");
        require(tree.roots().size() == 1, "replay changed capture");
    }

    private static Encoder recorder(List<String> events, TaskMonitorAdapter cancel) {
        return (Encoder)Proxy.newProxyInstance(Encoder.class.getClassLoader(), new Class<?>[]{Encoder.class},
            (proxy, method, args) -> {
                events.add(method.toGenericString() + Arrays.toString(args));
                if (cancel != null) cancel.cancel();
                return null;
            });
    }

    private static void writeAll(Encoder encoder, Program program) throws IOException {
        encoder.openElement(ELEM_FUNCTION);
        encoder.writeBool(ATTRIB_CUSTOM, true);
        encoder.writeSignedInteger(ATTRIB_EXTRAPOP, -20);
        encoder.writeUnsignedInteger(ATTRIB_ID, -1L);
        encoder.writeString(ATTRIB_NAME, "analyst <&> \" unicode \u03bb");
        encoder.writeStringIndexed(ATTRIB_NAME, 7, "indexed");
        encoder.writeSpace(ATTRIB_SPACE, program.getAddressFactory().getStackSpace());
        encoder.writeSpace(ATTRIB_SPACE, 2, "register");
        encoder.writeOpcode(ATTRIB_CODE, OpCode.CPUI_COPY);
        encoder.openElement(ELEM_ADDR);
        encoder.closeElement(ELEM_ADDR);
        encoder.closeElement(ELEM_FUNCTION);
    }

    private static void bounds() throws Exception {
        var tree = new GhidraEncoderTree(TaskMonitor.DUMMY);
        rejects(() -> tree.writeBool(ATTRIB_CUSTOM, true), "Misplaced");
        rejects(() -> tree.closeElement(ELEM_FUNCTION), "Unbalanced");
        tree.openElement(ELEM_FUNCTION);
        rejects(tree::roots, "Unclosed");
        rejects(() -> tree.closeElement(ELEM_ADDR), "Unbalanced");
        tree.openElement(ELEM_ADDR);
        tree.closeElement(ELEM_ADDR);
        rejects(() -> tree.writeBool(ATTRIB_CUSTOM, true), "Misplaced");
        tree.closeElement(ELEM_FUNCTION);
        var depth = new GhidraEncoderTree(TaskMonitor.DUMMY);
        for (int i = 0; i < 128; i++) depth.openElement(ELEM_ADDR);
        rejects(() -> depth.openElement(ELEM_ADDR), "nesting budget");
        var text = new GhidraEncoderTree(TaskMonitor.DUMMY);
        text.openElement(ELEM_FUNCTION);
        text.writeString(ATTRIB_NAME, "x".repeat(4_194_304));
        rejects(() -> text.writeStringIndexed(ATTRIB_NAME, 0, "x"), "text budget");
        var events = new GhidraEncoderTree(TaskMonitor.DUMMY);
        for (int i = 0; i < 50_000; i++) {
            events.openElement(ELEM_ADDR);
            events.closeElement(ELEM_ADDR);
        }
        rejects(() -> events.openElement(ELEM_ADDR), "event budget");
        var cancelled = new TaskMonitorAdapter(true);
        cancelled.cancel();
        rejects(() -> new GhidraEncoderTree(cancelled).openElement(ELEM_ADDR), "cancelled");
        rejects(() -> tree.roots().get(0).only(ELEM_PROTOTYPE), "shape");
    }

    private static void preservation(ProgramDB program) throws Exception {
        var entry = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
        var function = program.getFunctionManager().createFunction("analyst", entry,
            new AddressSet(entry, entry.add(31)), SourceType.USER_DEFINED);
        var manager = program.getDataTypeManager();
        var extended = new LongDoubleDataType(manager);
        function.updateFunction("__cdecl", new ReturnParameterImpl(extended, program),
            Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED,
            new ParameterImpl("analyst_argument", extended, program));
        function.addLocalVariable(new LocalVariableImpl("analyst_local", new IntegerDataType(manager), -16, program),
            SourceType.USER_DEFINED);
        var signature = new FunctionDefinitionDataType("AnalystCall", manager);
        signature.setReturnType(extended);
        signature.setArguments(new ParameterDefinition[]{new ParameterDefinitionImpl("call_argument", extended, null)});
        signature.setCallingConvention("__cdecl");
        HighFunctionDBUtil.writeOverride(function, entry.add(4), signature);
        String snapshot = function.getPrototypeString(false, false) + Arrays.toString(function.getAllVariables());
        var returnStorage = new VariableStorage(program, program.getRegister("ST0"));
        var inputStorage = new VariableStorage(program, 4, 10);
        var resolution = new GhidraParameterAllocation.Resolution(Map.of(1, inputStorage), Set.of(0), returnStorage);
        var decompiler = new DecompInterface();
        try {
            require(decompiler.openProgram(program), "open program");
            var original = encode(function, decompiler, 20, true);
            var view = GhidraAllocationDecompiler.functionView(function, resolution);
            var corrected = encode(view, decompiler, 4, false);
            require(corrected.children().stream().noneMatch(n -> n.id().equals(ELEM_OVERRIDE)), "proxy unexpectedly has DB overrides");
            require(original.only(ELEM_OVERRIDE).children().size() == 1, "missing real analyst override");
            var replacement = GhidraAllocationDecompiler.replaceSignature(original, corrected);
            require(replacement.only(ELEM_OVERRIDE).equals(original.only(ELEM_OVERRIDE)), "analyst override discarded");
            require(Long.valueOf(20).equals(replacement.only(ELEM_PROTOTYPE).attribute(ATTRIB_EXTRAPOP)), "caller extrapop discarded");
            require(Boolean.TRUE.equals(replacement.only(ELEM_PROTOTYPE).attribute(ATTRIB_CUSTOM)), "custom allocation absent");
            require(replacement.only(ELEM_PROTOTYPE).only(ELEM_RETURNSYM).equals(
                corrected.only(ELEM_PROTOTYPE).only(ELEM_RETURNSYM)), "wrong return carrier");
            var unknown = new GhidraEncoderTree.Node(ELEM_JUMPTABLELIST, List.of(), List.of());
            var withUnknown = new ArrayList<>(original.children()); withUnknown.add(unknown);
            var extendedOriginal = new GhidraEncoderTree.Node(original.id(), original.attributes(), withUnknown);
            require(GhidraAllocationDecompiler.replaceSignature(extendedOriginal, corrected).only(ELEM_JUMPTABLELIST).equals(unknown),
                "unrelated metadata lost");
            var local = function.getLocalVariables()[0];
            local.setName("changed_local", SourceType.USER_DEFINED);
            var wrongLocals = encode(view, decompiler, 4, false);
            rejects(() -> GhidraAllocationDecompiler.replaceSignature(original, wrongLocals), "local symbols");
            local.setName("analyst_local", SourceType.USER_DEFINED);
            var prototype = original.only(ELEM_OVERRIDE).only(ELEM_PROTOOVERRIDE).only(ELEM_PROTOTYPE);
            var overrideResolution = new GhidraParameterAllocation.SignatureResolution(returnStorage, List.of(inputStorage));
            var override = GhidraAllocationDecompiler.replaceOverrideStorage(prototype, overrideResolution, TaskMonitor.DUMMY);
            require(Boolean.TRUE.equals(override.attribute(ATTRIB_CUSTOM)), "override allocation absent");
            require(override.only(ELEM_INTERNALLIST).children().get(0).attributes().equals(
                prototype.only(ELEM_INTERNALLIST).children().get(0).attributes()), "override names or locks changed");
            rejects(() -> GhidraAllocationDecompiler.replaceOverrideStorage(override, overrideResolution, TaskMonitor.DUMMY), "explicit analyst");
            rejects(() -> GhidraAllocationDecompiler.replaceOverrideStorage(prototype,
                new GhidraParameterAllocation.SignatureResolution(returnStorage, List.of()), TaskMonitor.DUMMY), "parameter count");
            require(snapshot.equals(function.getPrototypeString(false, false) + Arrays.toString(function.getAllVariables())), "saved signature mutated");
            require(encode(function, decompiler, 20, true).equals(original), "saved encoding mutated");
        }
        finally { decompiler.dispose(); }
    }

    private static GhidraEncoderTree.Node encode(Function function, DecompInterface decompiler, int extrapop, boolean override)
            throws Exception {
        var program = function.getProgram();
        var high = new HighFunction(function, program.getLanguage(), program.getCompilerSpec(), decompiler.getDataTypeManager());
        high.grabFromFunction(extrapop, true, override);
        var encoder = new GhidraEncoderTree(TaskMonitor.DUMMY);
        high.encode(encoder, function.getSymbol().getID(), function.getParentNamespace(), function.getEntryPoint(), 1);
        return encoder.roots().get(0);
    }

    @FunctionalInterface private interface Attempt { void run() throws Exception; }
    private static void rejects(Attempt action, String message) throws Exception {
        try { action.run(); throw new AssertionError("Accepted invalid encoding: " + message); }
        catch (IOException expected) { require(expected.getMessage().contains(message), expected.toString()); }
    }
    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }
}
