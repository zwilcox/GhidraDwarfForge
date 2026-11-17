package ghidradwarfforge;

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.targets.ArmHfaParameterAllocation;

/** Real saved HFA profiles, recursive classification limits and parameter-budget admission. */
public final class ArmHfaAdmissionSmoke {
    private static final String BE8 = "ARM:LEBE:32:v8LEInstruction";
    private static int checks;

    private ArmHfaAdmissionSmoke() { }

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        run();
    }

    static void run() throws Exception {
        checks = 0;
        for (boolean big : new boolean[] {false, true}) {
            String language = big ? BE8 : "ARM:LE:32:v8";
            ByteOrder order = big ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
            int flags = big ? 0x05800400 : 0x05000400;
            try (var fixture = new Fixture(language, "default")) {
                fixture.signature(0, 1, false);
                var policy = fixture.policy(40, false, order, flags);
                corrected(fixture, policy, 0, big);
                for (var candidate : List.of(
                        fixture.policy(3, false, order, flags),
                        fixture.policy(40, true, order, flags),
                        fixture.policy(40, false, big ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN,
                            big ? 0x05000400 : 0x05800400),
                        fixture.policy(40, false, order, flags ^ 0x01000000),
                        fixture.policy(40, false, order, flags | 0x200))) {
                    require(candidate == GhidraParameterAllocation.UNCHANGED, "unsupported image admitted");
                    require(observe(fixture, candidate).isEmpty(), "unsupported image corrected storage");
                }
                try (var foreign = new Fixture(language, "default")) {
                    foreign.signature(0, 1, false);
                    require(observe(foreign, policy).isEmpty(), "captured policy trusted another program");
                    corrected(foreign, foreign.policy(40, false, order, flags), 0, big);
                }
                fixture.function.setCallingConvention(Function.UNKNOWN_CALLING_CONVENTION_STRING);
                require(observe(fixture, policy).isEmpty(), "unknown convention corrected storage");
                fixture.function.setCallingConvention("__stdcall");
                corrected(fixture, policy, 0, big);
                for (int depth : new int[] {60, 61, 62}) {
                    // Each wrapper and the two floating leaves consume one visit.
                    fixture.signature(depth, 1, false);
                    if (depth <= 61) corrected(fixture, policy, 0, big);
                    else require(observe(fixture, policy).isEmpty(), "over-budget nested HFA corrected");
                }
                fixture.signature(0, 1, true);
                require(fixture.function.getParameterCount() == 2 && fixture.function.getParameter(0).isAutoParameter(),
                    "large return must introduce an actual hidden return pointer");
                corrected(fixture, policy, 1, big);
                for (int count : new int[] {4096, 4097}) {
                    fixture.signature(0, count, false);
                    require(fixture.function.getParameterCount() == count, "parameter budget fixture changed count");
                    if (count == 4096) corrected(fixture, policy, 0, big);
                    else require(observe(fixture, policy).isEmpty(), "over-budget signature corrected");
                }
            }
            for (String compiler : List.of("windows", "apcs")) {
                try (var fixture = new Fixture(language, compiler)) {
                    var policy = fixture.policy(40, false, order, flags);
                    require(policy == GhidraParameterAllocation.UNCHANGED, "unaudited compiler admitted");
                }
            }
        }
        System.out.println("arm-hfa-admission=PASS checks=" + checks);
    }

    private static void corrected(Fixture fixture, GhidraParameterAllocation policy, int ordinal, boolean big)
            throws Exception {
        var result = observe(fixture, policy);
        require(result.keySet().equals(java.util.Set.of(ordinal)), "only the HFA argument should change: " + result);
        var first = new Varnode(fixture.program.getRegister("s0").getAddress(), 4);
        var second = new Varnode(fixture.program.getRegister("s1").getAddress(), 4);
        require(Arrays.equals(result.get(ordinal).getVarnodes(), big ? new Varnode[] {first, second} :
            new Varnode[] {second, first}), "HFA pieces must preserve the target member order");
    }

    private static Map<Integer, VariableStorage> observe(Fixture fixture, GhidraParameterAllocation policy)
            throws Exception {
        var parameters = fixture.function.getParameters();
        var storage = Arrays.stream(parameters).map(p -> p.getVariableStorage()).toList();
        var types = Arrays.stream(parameters).map(p -> p.getFormalDataType()).toList();
        long modification = fixture.program.getModificationNumber();
        byte[] original = Files.readAllBytes(fixture.image);
        var diagnostics = new ArrayList<String>();
        var result = policy.corrections(fixture.function, TaskMonitor.DUMMY, diagnostics::add);
        require(fixture.program.getModificationNumber() == modification, "correction modified the saved program");
        require(storage.equals(Arrays.stream(fixture.function.getParameters()).map(p -> p.getVariableStorage()).toList()),
            "correction modified saved storage");
        require(types.equals(Arrays.stream(fixture.function.getParameters()).map(p -> p.getFormalDataType()).toList()),
            "correction modified formal types");
        require(Arrays.equals(original, Files.readAllBytes(fixture.image)), "correction modified the original ELF");
        require(diagnostics.size() == result.size(), "diagnostics do not match the justified corrections");
        return result;
    }

    private static final class Fixture implements AutoCloseable {
        final Object owner = new Object();
        final ProgramDB program;
        final Function function;
        final int transaction;
        final Path image;

        Fixture(String languageId, String compilerId) throws Exception {
            var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(languageId));
            program = new ProgramDB("hfa-admission", language,
                language.getCompilerSpecByID(new CompilerSpecID(compilerId)), owner);
            image = Files.createTempFile("arm-hfa-admission", ".elf");
            transaction = program.startTransaction("HFA admission fixture");
            var entry = language.getDefaultSpace().getAddress(0x1000);
            function = program.getFunctionManager().createFunction("aggregate", entry,
                new AddressSet(entry, entry.add(3)), SourceType.USER_DEFINED);
        }

        GhidraParameterAllocation policy(int machine, boolean wide, ByteOrder order, int flags) throws Exception {
            var header = ByteBuffer.allocate(wide ? 64 : 52).order(order);
            header.put(new byte[] {0x7f, 'E', 'L', 'F', (byte) (wide ? 2 : 1),
                (byte) (order == ByteOrder.BIG_ENDIAN ? 2 : 1), 1});
            header.putShort(16, (short) 2).putShort(18, (short) machine).putInt(20, 1);
            header.putInt(wide ? 48 : 36, flags).putShort(wide ? 52 : 40, (short) header.capacity());
            Files.write(image, header.array());
            return ArmHfaParameterAllocation.forProgram(program, ElfImage.read(image), TaskMonitor.DUMMY,
                message -> { throw new AssertionError(message); });
        }

        void signature(int depth, int count, boolean hiddenReturn) throws Exception {
            var aggregate = new StructureDataType("TwoFloats", 0, program.getDataTypeManager());
            aggregate.add(FloatDataType.dataType, "first", null);
            aggregate.add(FloatDataType.dataType, "second", null);
            DataType type = aggregate;
            for (int index = 0; index < depth; index++) {
                var wrapper = new StructureDataType("Depth_" + depth + "_" + index, 0, program.getDataTypeManager());
                wrapper.add(type, "inner", null);
                type = wrapper;
            }
            var parameters = new ArrayList<ParameterImpl>();
            for (int index = 0; index < count; index++) {
                parameters.add(new ParameterImpl("arg" + index, index == 0 ? type : IntegerDataType.dataType, program));
            }
            DataType result = hiddenReturn ? new StructureDataType("LargeReturn", 32, program.getDataTypeManager()) :
                VoidDataType.dataType;
            function.updateFunction("__stdcall", new ReturnParameterImpl(result, program),
                Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED,
                parameters.toArray(ParameterImpl[]::new));
        }

        @Override
        public void close() throws Exception {
            try { program.endTransaction(transaction, false); }
            finally {
                try { program.release(owner); }
                finally { Files.deleteIfExists(image); }
            }
        }
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
