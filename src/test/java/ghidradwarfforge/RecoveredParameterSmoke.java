package ghidradwarfforge;

import java.io.File;
import java.math.BigInteger;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import db.DBHandle;
import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.data.OpenMode;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidradwarfforge.GhidraSyntheticSource.RecoveredParameter;
import ghidradwarfforge.GhidraSyntheticSource.ParameterRecovery;
import ghidradwarfforge.locations.VariableStorageModel;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.TypeGraph;

/** Recovered parameter metadata without fabricated storage, preserving stronger signatures. */
public final class RecoveredParameterSmoke {
    private record Target(String language, String map, String code) { }
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (Target target : List.of(
                new Target("x86:LE:64:default", "x86_64", "90c3"),
                new Target("AARCH64:LE:64:v8A", "aarch64", "1f2003d5c0035fd6"),
                new Target("ARM:LE:32:v8", "arm", "00f020e31eff2fe1"),
                new Target("MIPS:BE:32:default", "mips", "0000000003e0000800000000"),
                new Target("MIPS:LE:32:default", "mipsel", "000000000800e00300000000"))) {
            check(target);
        }
        System.out.println("recovered-parameter-smoke=PASS checks=" + checks);
    }

    private static void check(Target target) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(target.language()));
        var compiler = target.map().equals("x86_64")
            ? language.getCompilerSpecByID(new CompilerSpecID("gcc")) : language.getDefaultCompilerSpec();
        Object owner = new Object();
        var program = new ProgramDB("recovered-parameters", language, compiler, owner);
        var directory = Files.createTempDirectory("forge-recovered-parameters-");
        var saved = directory.resolve("program.db");
        try {
            int transaction = program.startTransaction("return provenance controls");
            try {
                create(program, target, 0x1000, "unknown");
                int offset = 0x1100;
                for (SourceType source : List.of(SourceType.USER_DEFINED, SourceType.IMPORTED, SourceType.ANALYSIS)) {
                    var known = create(program, target, offset, source.name());
                    known.setReturnType(VoidDataType.dataType, source);
                    offset += 0x100;
                }
                var custom = create(program, target, 0x1400, "custom");
                custom.setCustomVariableStorage(true);
                var pointer = create(program, target, 0x1500, "pointer");
                pointer.setReturnType(new PointerDataType(IntegerDataType.dataType,
                    program.getDataTypeManager()), SourceType.USER_DEFINED);
                var listed = create(program, target, 0x1600, "listed");
                listed.updateFunction(null, listed.getReturn(), Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                    true, SourceType.DEFAULT, new ParameterImpl("existing", IntegerDataType.dataType, program, SourceType.DEFAULT));
                var conflict = create(program, target, 0x1700, "conflict");
                conflict.addLocalVariable(new LocalVariableImpl("seed", 0, IntegerDataType.dataType,
                    VariableStorage.UNASSIGNED_STORAGE, program), SourceType.USER_DEFINED);
                var varargs = create(program, target, 0x1800, "varargs");
                varargs.setVarArgs(true);
                observe(program, target);
            }
            finally {
                program.endTransaction(transaction, true);
            }
            program.getDBHandle().saveAs(saved.toFile(), false, TaskMonitor.DUMMY);
            byte[] before = Files.readAllBytes(saved);
            var mtime = Files.getLastModifiedTime(saved);
            Object reopenedOwner = new Object();
            DBHandle handle = new DBHandle(saved.toFile());
            ProgramDB reopened = null;
            try {
                reopened = new ProgramDB(handle, OpenMode.IMMUTABLE, TaskMonitor.DUMMY, reopenedOwner);
                observe(reopened, target);
            }
            finally {
                if (reopened != null) {
                    reopened.release(reopenedOwner);
                }
                else {
                    handle.close();
                }
            }
            require(Arrays.equals(before, Files.readAllBytes(saved)) &&
                mtime.equals(Files.getLastModifiedTime(saved)), "immutable extraction changed database");
            System.out.println("recovered-parameter-target=PASS " + target.language());
        }
        finally {
            program.release(owner);
            Files.deleteIfExists(saved);
            Files.deleteIfExists(directory);
        }
    }

    private static Function create(ProgramDB program, Target target, long entry, String name) throws Exception {
        byte[] code = HexFormat.of().parseHex(target.code());
        var start = program.getAddressFactory().getDefaultAddressSpace().getAddress(entry);
        var body = new AddressSet(start, start.add(code.length - 1));
        var block = program.getMemory().createInitializedBlock(name, start, code.length,
            (byte) 0, TaskMonitor.DUMMY, false);
        block.setExecute(true);
        program.getMemory().setBytes(start, code);
        if (target.map().equals("arm")) {
            program.getProgramContext().setValue(program.getRegister("TMode"), start,
                body.getMaxAddress(), BigInteger.ZERO);
        }
        require(new DisassembleCommand(start, body, true).applyTo(program, TaskMonitor.DUMMY),
            "fixture did not decode");
        return program.getFunctionManager().createFunction(name, start, body, SourceType.USER_DEFINED);
    }

    private static ProgramTypeModel extract(ProgramDB program, Target target, Map<Long, ParameterRecovery> parameters,
            TaskMonitor monitor, List<String> diagnostics) throws Exception {
        var symbols = new ArrayList<FunctionSymbol>();
        for (Function function : program.getFunctionManager().getFunctions(true)) {
            symbols.add(new FunctionSymbol(function.getName(), function.getEntryPoint().getOffset() - 0x800,
                function.getBody().getNumAddresses()));
        }
        return GhidraTypeGraph.extract(program, symbols, target.map(), 0x800, monitor, diagnostics::add, Map.of(), parameters);
    }

    private static void observe(ProgramDB program, Target target) throws Exception {
        var baseline = extract(program, target, Map.of(), TaskMonitor.DUMMY, new ArrayList<>());
        var pointer = new PointerDataType(IntegerDataType.dataType, program.getDataTypeManager());
        var candidates = List.of(new RecoveredParameter("seed", IntegerDataType.dataType),
            new RecoveredParameter("cursor", pointer), new RecoveredParameter("scale", DoubleDataType.dataType));
        var recovery = new ParameterRecovery(candidates, null);
        var all = new java.util.HashMap<Long, ParameterRecovery>();
        for (var function : baseline.functions()) { all.put(function.address(), recovery); }
        var diagnostics = new ArrayList<String>();
        var model = extract(program, target, all, TaskMonitor.DUMMY, diagnostics);
        require(model.functions().size() == 9, "fixture function count changed");
        for (var signature : model.functions()) {
            var prior = baseline.functions().stream().filter(f -> f.name().equals(signature.name())).findFirst().orElseThrow();
            if (!signature.name().equals("unknown")) {
                require(signature.equals(prior), "overrode stronger/existing/unsupported signature " + signature.name());
                continue;
            }
            require(signature.signatureSource().equals("DEFAULT") && signature.returnType().equals(prior.returnType()),
                "parameter recovery changed return or signature provenance");
            require(signature.parameters().stream().map(TypeGraph.Parameter::name).toList().equals(List.of("seed", "cursor", "scale")),
                "recovered parameter order/names differ");
            var types = model.types().byKey();
            for (int i = 0; i < candidates.size(); i++) {
                var parameter = signature.parameters().get(i);
                require(!parameter.artificial(), "invented hidden parameter");
                require(types.get(parameter.type().key()).byteSize() == candidates.get(i).type().getLength(), "lost parameter width");
            }
            require(types.get(signature.parameters().get(1).type().key()) instanceof TypeGraph.IndirectionType,
                "lost pointer type");
        }
        var inferred = model.variableStorage().variables().stream().filter(v -> v.functionName().equals("unknown")).toList();
        require(inferred.size() == 3, "missing explicit location omissions");
        for (var variable : inferred) {
            require(!variable.hasDefensibleLocation() && variable.kind() == VariableStorageModel.VariableKind.PARAMETER,
                "invented parameter location");
            require(variable.functionAddress() == 0x800, "parameter used wrong address coordinate system");
            for (var range : variable.locations()) {
                require(range.evidence().confidence() == VariableStorageModel.Confidence.DECOMPILER,
                    "inference mislabeled as curated");
                require(range.storage() instanceof VariableStorageModel.UnavailableStorage missing &&
                    missing.reason() == VariableStorageModel.OmissionReason.UNKNOWN_LIFETIME,
                    "missing honest lifetime omission");
            }
        }
        require(model.variableStorage().variables().stream().filter(v -> !v.functionName().equals("unknown")).toList()
            .equals(baseline.variableStorage().variables()), "changed existing variable storage");
        require(diagnostics.stream().filter(d -> d.startsWith("Using decompiler-recovered parameter names/types")).count() == 1,
            "missing inference diagnostic");
        require(diagnostics.stream().anyMatch(d -> d.startsWith("Omitted decompiler parameter recovery for conflict:")),
            "missing local-name conflict diagnostic");
        require(model.equals(extract(program, target, all, TaskMonitor.DUMMY, new ArrayList<>())), "nondeterministic extraction");
        for (ParameterRecovery rejected : List.of(
                new ParameterRecovery(List.of(), "unresolved high parameter"),
                new ParameterRecovery(List.of(candidates.get(0), candidates.get(0)), null),
                new ParameterRecovery(List.of(candidates.get(0), new RecoveredParameter("later", Undefined8DataType.dataType)), null),
                new ParameterRecovery(List.of(new RecoveredParameter("value", VoidDataType.dataType)), null),
                new ParameterRecovery(List.of(new RecoveredParameter("value", new StructureDataType("UnknownAbi", 16))), null))) {
            var omitted = new ArrayList<String>();
            require(extract(program, target, Map.of(0x800L, rejected), TaskMonitor.DUMMY, omitted).equals(baseline),
                "partial or unsupported parameter list changed model");
            require(omitted.stream().anyMatch(d -> d.startsWith("Omitted decompiler parameter recovery for unknown:")),
                "parameter omission was silent");
        }
        require(extract(program, target, Map.of(0x1000L, recovery), TaskMonitor.DUMMY, new ArrayList<>()).equals(baseline),
            "un-normalized parameter evidence used");
        try {
            new ParameterRecovery(candidates, "");
            throw new AssertionError("ambiguous evidence accepted");
        }
        catch (IllegalArgumentException expected) { checks++; }
        try {
            recovery.parameters().clear();
            throw new AssertionError("mutable ordered parameter evidence");
        }
        catch (UnsupportedOperationException expected) { checks++; }
        var cancelled = new TaskMonitorAdapter(true);
        cancelled.cancel();
        try {
            extract(program, target, all, cancelled, new ArrayList<>());
            throw new AssertionError("ignored cancellation");
        }
        catch (CancelledException expected) { checks++; }
        require(extract(program, target, Map.of(), TaskMonitor.DUMMY, new ArrayList<>()).equals(baseline),
            "recovery changed saved signature or variable data");
    }

    private static void require(boolean value, String message) {
        checks++;
        if (!value) {
            throw new AssertionError(message);
        }
    }
}
