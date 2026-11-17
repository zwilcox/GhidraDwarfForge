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
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Structure;
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
import ghidradwarfforge.targets.ArmCompositeParameterAllocation;

/** Saved-program admission and bounds for the audited BE8 aggregate correction. */
public final class ArmCompositeAdmissionSmoke {
    private static final String BE8 = "ARM:LEBE:32:v8LEInstruction";
    private static int checks;

    private ArmCompositeAdmissionSmoke() { }

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        run();
    }

    static void run() throws Exception {
        checks = 0;
        try (var fixture = new Fixture(BE8, "default")) {
            fixture.signature(0, 1, false);
            var policy = fixture.policy(40, false, ByteOrder.BIG_ENDIAN, 0x05800400);
            corrected(fixture, policy, 4, 0);
            for (var candidate : List.of(
                    fixture.policy(3, false, ByteOrder.BIG_ENDIAN, 0x05800400),
                    fixture.policy(40, true, ByteOrder.BIG_ENDIAN, 0x05800400),
                    fixture.policy(40, false, ByteOrder.LITTLE_ENDIAN, 0x05000400),
                    fixture.policy(40, false, ByteOrder.BIG_ENDIAN, 0x04800400),
                    fixture.policy(40, false, ByteOrder.BIG_ENDIAN, 0x05800600))) {
                require(candidate == GhidraParameterAllocation.UNCHANGED, "unsupported image admitted");
                require(observe(fixture, candidate).isEmpty(), "unsupported image corrected storage");
            }
            try (var foreign = new Fixture(BE8, "default")) {
                foreign.signature(0, 1, false);
                require(observe(foreign, policy).isEmpty(), "captured policy trusted another program");
                corrected(foreign, foreign.policy(40, false, ByteOrder.BIG_ENDIAN, 0x05800400), 4, 0);
            }
            fixture.function.setCallingConvention(Function.UNKNOWN_CALLING_CONVENTION_STRING);
            require(observe(fixture, policy).isEmpty(), "unknown convention corrected storage");
            fixture.function.setCallingConvention("__stdcall");
            corrected(fixture, policy, 4, 0);
            for (int depth : new int[] {63, 64, 65}) {
                fixture.signature(depth, 1, false);
                require(fixture.function.getParameter(4).getFormalDataType() instanceof TypeDef alias &&
                    alias.getBaseDataType() instanceof Structure, "Ghidra must resolve the nested typedef base");
                corrected(fixture, policy, 4, 0);
            }
            fixture.signature(0, 1, true);
            require(fixture.function.getParameterCount() == 6 && fixture.function.getParameter(0).isAutoParameter(),
                "large return must introduce an actual hidden return pointer");
            corrected(fixture, policy, 5, 4);
            for (int count : new int[] {4096, 4097}) {
                fixture.signature(0, count, false);
                require(fixture.function.getParameterCount() == count, "parameter budget fixture changed count");
                if (count == 4096) corrected(fixture, policy, 4, 0);
                else require(observe(fixture, policy).isEmpty(), "over-budget signature corrected");
            }
        }
        for (String[] profile : new String[][] {{"ARM:LE:32:v8", "default"}, {BE8, "windows"}, {BE8, "apcs"}}) {
            try (var fixture = new Fixture(profile[0], profile[1])) {
                var policy = fixture.policy(40, false, ByteOrder.BIG_ENDIAN, 0x05800400);
                require(policy == GhidraParameterAllocation.UNCHANGED, "unaudited language/compiler admitted");
            }
        }
        System.out.println("arm-composite-admission=PASS checks=" + checks);
    }

    private static void corrected(Fixture fixture, GhidraParameterAllocation policy, int ordinal, long offset)
            throws Exception {
        var result = observe(fixture, policy);
        var expected = new Varnode(fixture.program.getAddressFactory().getStackSpace().getAddress(offset), 3);
        require(result.keySet().equals(java.util.Set.of(ordinal)), "only the aggregate argument should change: " + result);
        require(Arrays.equals(result.get(ordinal).getVarnodes(), new Varnode[] {expected}),
            "three aggregate bytes must precede padding at stack offset " + offset);
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
            program = new ProgramDB("aggregate-admission", language,
                language.getCompilerSpecByID(new CompilerSpecID(compilerId)), owner);
            image = Files.createTempFile("arm-composite-admission", ".elf");
            transaction = program.startTransaction("aggregate admission fixture");
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
            return ArmCompositeParameterAllocation.forProgram(program, ElfImage.read(image), TaskMonitor.DUMMY,
                message -> { throw new AssertionError(message); });
        }

        void signature(int aliases, int count, boolean hiddenReturn) throws Exception {
            var aggregate = new StructureDataType("ThreeBytes", 0, program.getDataTypeManager());
            aggregate.add(new ArrayDataType(ByteDataType.dataType, 3, 1, program.getDataTypeManager()), "bytes", null);
            DataType type = aggregate;
            for (int index = 0; index < aliases; index++) {
                type = new TypedefDataType(CategoryPath.ROOT, "Alias_" + aliases + "_" + index, type,
                    program.getDataTypeManager());
            }
            var parameters = new ArrayList<ParameterImpl>();
            for (int index = 0; index < Math.max(5, count); index++) {
                parameters.add(new ParameterImpl("arg" + index, index == 4 ? type : IntegerDataType.dataType, program));
            }
            DataType result = hiddenReturn ? new StructureDataType("LargeReturn", 8, program.getDataTypeManager()) :
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
