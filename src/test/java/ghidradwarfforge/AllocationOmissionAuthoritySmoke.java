package ghidradwarfforge;

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongDoubleDataType;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.targets.I386ParameterAllocation;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.TypeGraph;

/** A faulty allocation policy cannot erase explicit analyst formals from the exported type graph. */
public final class AllocationOmissionAuthoritySmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        run();
    }

    public static void run() throws Exception {
        Object owner = new Object();
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
        var program = new ProgramDB("allocation-authority", language,
            language.getCompilerSpecByID(new CompilerSpecID("gcc")), owner);
        var file = Files.createTempFile("forge-allocation-authority-", ".elf");
        int transaction = program.startTransaction("curated definitions and declarations");
        try {
            byte[] original = header();
            Files.write(file, original);
            var policy = I386ParameterAllocation.forProgram(program, ElfImage.read(file), TaskMonitor.DUMMY, ignored -> { });
            require(policy.hasReturnCorrections(), "audited i386 correction policy is selected");
            var entry = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
            program.getMemory().createInitializedBlock(".text", entry, 2, (byte) 0, TaskMonitor.DUMMY, false);
            program.getMemory().setBytes(entry, new byte[] { (byte) 0x90, (byte) 0xc3 });
            require(new ghidra.app.cmd.disassemble.DisassembleCommand(entry, null, true).applyTo(program),
                "real NOP/RET instruction body disassembles");
            var definition = program.getFunctionManager().createFunction("curated_definition", entry,
                new AddressSet(entry, entry.add(1)), SourceType.USER_DEFINED);
            var declaration = program.getExternalManager().addExtFunction("libfixture", "curated_declaration", null,
                SourceType.USER_DEFINED).getFunction();
            for (DataType returned : List.of(new IntegerDataType(program.getDataTypeManager()),
                    new LongDoubleDataType(program.getDataTypeManager()))) {
                for (var function : List.of(definition, declaration)) {
                    function.updateFunction("__cdecl", new ReturnParameterImpl(returned, program),
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED,
                        new ParameterImpl("analyst_input", new IntegerDataType(program.getDataTypeManager()), program));
                }
                int automatic = returned instanceof LongDoubleDataType ? 1 : 0;
                require(definition.getAutoParameterCount() == automatic && declaration.getAutoParameterCount() == automatic,
                    "actual compiler supplies only the expected hidden result pointer");
                String saved = snapshot(definition) + snapshot(declaration);
                long modification = program.getModificationNumber();
                var entries = new ArrayList<GhidraCallParameters.Entry>();
                var baseline = extract(program, definition, policy, entries);
                require(baseline.functions().size() == 1 && baseline.functionDeclarations().size() == 1,
                    "both curated signatures exported");
                var body = baseline.functions().getFirst();
                var external = baseline.functionDeclarations().getFirst();
                for (var parameters : List.of(body.parameters(), external.parameters())) {
                    require(parameters.size() == 1 && parameters.getFirst().name().equals("analyst_input") &&
                        !parameters.getFirst().artificial(), "omit only automatic pointer, retain named explicit parameter");
                    var type = baseline.types().byKey().get(parameters.getFirst().type().key());
                    require(type instanceof TypeGraph.BaseType base && base.encoding() == TypeGraph.BaseEncoding.SIGNED &&
                        base.byteSize() == 4, "explicit signed integer type retained");
                }
                var returnType = baseline.types().byKey().get(body.returnType().key());
                require(body.returnType().equals(external.returnType()) && returnType instanceof TypeGraph.BaseType base &&
                    base.encoding() == (automatic == 1 ? TypeGraph.BaseEncoding.FLOAT : TypeGraph.BaseEncoding.SIGNED) &&
                    base.byteSize() == (automatic == 1 ? 12 : 4) && base.valueByteSize() == (automatic == 1 ? 10 : 4),
                    "formal return retains ABI size and value width independently of hidden carrier");
                require(entries.size() == 1 && entries.getFirst().ordinal() == 0 && entries.getFirst().pieces().size() == 1 &&
                    entries.getFirst().pieces().getFirst().address().isStackAddress() &&
                    entries.getFirst().pieces().getFirst().address().getOffset() == 4 &&
                    entries.getFirst().pieces().getFirst().bytes() == 4, "corrected explicit entry carrier follows return address");
                for (boolean externalFault : List.of(false, true)) {
                    try {
                        extract(program, definition, faulty(policy, externalFault), new ArrayList<>());
                        throw new AssertionError("allocation policy erased an explicit " + (externalFault ? "declaration" : "definition") + " parameter");
                    }
                    catch (IllegalStateException expected) {
                        require(expected.getMessage().equals("Cannot omit an explicit parameter"), "reject omission at authority boundary");
                    }
                    require(saved.equals(snapshot(definition) + snapshot(declaration)) && program.getModificationNumber() == modification,
                        "failed extraction preserves saved names, types, storage, ordinals and modification number");
                    require(extract(program, definition, policy, new ArrayList<>()).equals(baseline),
                        "clean retry deterministically recovers complete type model");
                }
                require(Arrays.equals(original, Files.readAllBytes(file)), "allocation leaves original ELF unchanged");
            }
        }
        finally {
            program.endTransaction(transaction, false);
            program.release(owner);
            Files.deleteIfExists(file);
        }
        System.out.println("allocation-omission-authority=PASS checks=" + checks);
    }

    private static ProgramTypeModel extract(ProgramDB program, Function function, GhidraParameterAllocation policy,
            List<GhidraCallParameters.Entry> entries) throws CancelledException {
        return GhidraTypeGraph.extract(program, List.of(new FunctionSymbol(function.getName(), 0x1000, 2)),
            TargetRegisterMap.forTarget("x86"), 0, TaskMonitor.DUMMY, ignored -> { }, Map.of(), Map.of(), Map.of(),
            policy, entries::add);
    }

    private static GhidraParameterAllocation faulty(GhidraParameterAllocation delegate, boolean externalFault) {
        return new GhidraParameterAllocation() {
            @Override public Map<Integer, VariableStorage> corrections(Function function, TaskMonitor monitor,
                    Consumer<String> diagnostic) throws CancelledException {
                return resolve(function, monitor, diagnostic).storage();
            }
            @Override public Resolution resolve(Function function, TaskMonitor monitor, Consumer<String> diagnostic)
                    throws CancelledException {
                var result = delegate.resolve(function, monitor, diagnostic);
                return externalFault ? result : omitExplicit(function, result);
            }
            @Override public Resolution resolveDeclaration(Function function, TaskMonitor monitor, Consumer<String> diagnostic)
                    throws CancelledException {
                var result = delegate.resolveDeclaration(function, monitor, diagnostic);
                return externalFault ? omitExplicit(function, result) : result;
            }
        };
    }

    private static GhidraParameterAllocation.Resolution omitExplicit(Function function, GhidraParameterAllocation.Resolution result) {
        int ordinal = Arrays.stream(function.getParameters()).filter(parameter -> !parameter.isAutoParameter())
            .findFirst().orElseThrow().getOrdinal();
        var omitted = new HashSet<>(result.omittedAutomaticParameters());
        omitted.add(ordinal);
        var storage = new HashMap<>(result.storage());
        storage.remove(ordinal);
        return new GhidraParameterAllocation.Resolution(storage, omitted, result.returnStorage());
    }

    private static String snapshot(Function function) {
        return function.getPrototypeString(false, false) + ":" + function.getReturn().getVariableStorage() + ":" +
            Arrays.stream(function.getParameters()).map(parameter -> parameter.getName() + ":" + parameter.getOrdinal() + ":" +
                parameter.getFormalDataType().getPathName() + ":" + parameter.getVariableStorage() + ":" + parameter.getSource()).toList();
    }

    private static byte[] header() {
        var bytes = ByteBuffer.allocate(52).order(ByteOrder.LITTLE_ENDIAN);
        bytes.putInt(0, 0x464c457f); bytes.put(4, (byte) 1); bytes.put(5, (byte) 1); bytes.put(6, (byte) 1);
        bytes.putShort(16, (short) 2); bytes.putShort(18, (short) 3); bytes.putInt(20, 1);
        bytes.putShort(40, (short) 52); bytes.putShort(42, (short) 32); bytes.putShort(46, (short) 40);
        return bytes.array();
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }
}
