package ghidradwarfforge;

import java.io.File;
import java.math.BigInteger;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

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
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.dwarf.DwarfLocationExpression;
import ghidradwarfforge.locations.VariableStorageModel.RegisterRelativeStorage;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.TypeGraph;

/** Concrete curated signatures, ABI-generated hidden parameters and immutable reopen. */
public final class FormalFunctionReturnSmoke {
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
        System.out.println("formal-function-return-smoke=PASS checks=" + checks);
    }

    private static void check(Target target) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(target.language()));
        var compiler = target.map().equals("x86_64")
            ? language.getCompilerSpecByID(new CompilerSpecID("gcc")) : language.getDefaultCompilerSpec();
        Object owner = new Object();
        var program = new ProgramDB("formal-function-returns", language, compiler, owner);
        var directory = Files.createTempDirectory("forge-formal-returns-");
        var saved = directory.resolve("program.db");
        try {
            int transaction = program.startTransaction("curated return types");
            try {
                var manager = program.getDataTypeManager();
                var shape = new StructureDataType("ReturnTriple", 0, manager);
                for (String name : List.of("first", "second", "third")) {
                    shape.add(new UnsignedLongLongDataType(manager), name, null);
                }
                DataType aggregate = manager.resolve(shape, DataTypeConflictHandler.DEFAULT_HANDLER);
                create(program, target, 0x1000, "aggregate", aggregate);
                create(program, target, 0x1100, "pointer", new PointerDataType(aggregate, manager));
                create(program, target, 0x1200, "scalar", new IntegerDataType(manager));
                create(program, target, 0x1300, "nothing", VoidDataType.dataType);
                var custom = create(program, target, 0x1400, "custom", aggregate);
                // Ghidra deliberately materializes effective ABI types when converting to custom storage.
                custom.setCustomVariableStorage(true);
                var argument = create(program, target, 0x1500, "aggregate_argument", VoidDataType.dataType);
                argument.updateFunction(null, argument.getReturn(), Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                    true, SourceType.USER_DEFINED,
                    new ParameterImpl("seed", aggregate, program, SourceType.USER_DEFINED));
                var external = program.getExternalManager().addExtFunction(
                    "analyst_library", "external_aggregate", null, SourceType.USER_DEFINED).getFunction();
                external.updateFunction(compiler.getDefaultCallingConvention().getName(),
                    new ghidra.program.model.listing.ReturnParameterImpl(aggregate, program),
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED,
                    new ParameterImpl("seed", new IntegerDataType(manager), program, SourceType.USER_DEFINED));
                observe(program, target);
                var monitor = new TaskMonitorAdapter(true);
                monitor.cancel();
                try {
                    extract(program, target, monitor);
                    throw new AssertionError("type extraction ignored cancellation");
                }
                catch (CancelledException expected) {
                    checks++;
                }
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
            System.out.println("formal-function-return-target=PASS " + target.language());
        }
        finally {
            program.release(owner);
            Files.deleteIfExists(saved);
            Files.deleteIfExists(directory);
        }
    }

    private static Function create(ProgramDB program, Target target, long entry,
            String name, DataType type) throws Exception {
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
        var function = program.getFunctionManager().createFunction(name, start, body, SourceType.USER_DEFINED);
        function.setReturnType(type, SourceType.USER_DEFINED);
        function.updateFunction(null, function.getReturn(), Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
            true, SourceType.USER_DEFINED,
            new ParameterImpl("seed", new IntegerDataType(program.getDataTypeManager()), program, SourceType.USER_DEFINED));
        return function;
    }

    private static ProgramTypeModel extract(ProgramDB program, Target target, TaskMonitor monitor) throws Exception {
        var symbols = new java.util.ArrayList<FunctionSymbol>();
        for (Function function : program.getFunctionManager().getFunctions(true)) {
            symbols.add(new FunctionSymbol(function.getName(), function.getEntryPoint().getOffset(),
                function.getBody().getNumAddresses()));
        }
        return GhidraTypeGraph.extract(program, symbols, target.map(), 0, monitor, ignored -> { });
    }

    private static void observe(ProgramDB program, Target target) throws Exception {
        var model = extract(program, target, TaskMonitor.DUMMY);
        require(model.functions().size() == 6, "lost a concrete function signature");
        require(model.functionDeclarations().size() == 1, "lost external aggregate declaration");
        var external = model.functionDeclarations().get(0);
        require(external.parameters().size() == 2 && external.parameters().get(0).returnStorage() &&
            external.parameters().get(0).artificial() && !external.parameters().get(1).returnStorage(),
            "external return carrier became a user argument");
        require(model.types().byKey().get(external.returnType().key()) instanceof TypeGraph.AggregateType aggregate &&
            aggregate.byteSize() == 24, "external formal aggregate return changed");
        var types = model.types().byKey();
        for (var signature : model.functions()) {
            var function = program.getFunctionManager().getFunctionAt(
                program.getAddressFactory().getDefaultAddressSpace().getAddress(signature.address()));
            var returnType = types.get(signature.returnType().key());
            require(signature.signatureSource().equals("USER_DEFINED"), "lost analyst signature provenance");
            switch (signature.name()) {
                case "aggregate" -> {
                    require(function.getReturn().isForcedIndirect(), "fixture must use indirect aggregate return");
                    require(function.getReturn().getFormalDataType() instanceof Structure &&
                        !(function.getReturnType() instanceof Structure), "formal/effective distinction missing");
                    require(returnType instanceof TypeGraph.AggregateType && returnType.byteSize() == 24,
                        "exported return must be the formal aggregate, not its ABI carrier: " + returnType);
                    var aggregate = (TypeGraph.AggregateType) returnType;
                    require(aggregate.members().stream().map(TypeGraph.Member::byteOffset).toList().equals(List.of(0L, 8L, 16L)),
                        "aggregate layout changed");
                    require(signature.parameters().size() == 2 && signature.parameters().get(0).artificial() && signature.parameters().get(0).returnStorage() &&
                        !signature.parameters().get(1).artificial() && !signature.parameters().get(1).returnStorage(), "hidden/explicit parameter distinction lost");
                    var hidden = types.get(signature.parameters().get(0).type().key());
                    require(hidden instanceof TypeGraph.IndirectionType pointer &&
                        pointer.target().equals(signature.returnType()), "hidden return pointer lost canonical aggregate");
                }
                case "aggregate_argument" -> {
                    var parameter = signature.parameters().get(0);
                    require(types.get(parameter.type().key()) instanceof TypeGraph.AggregateType &&
                        types.get(parameter.type().key()).byteSize() == 24, "by-value parameter lost formal type");
                    if (function.getParameter(0).isForcedIndirect()) {
                        var variables = model.variableStorage().variables().stream()
                            .filter(variable -> variable.functionAddress() == signature.address())
                            .toList();
                        require(target.map().equals("aarch64") && variables.size() == 1,
                            "unexpected forced-indirect fixture ABI");
                        var variable = variables.getFirst();
                        require(variable.name().equals("seed") && variable.byteSize() == 24 &&
                            variable.locations().size() == 1, "formal argument became its pointer carrier");
                        var range = variable.locations().getFirst();
                        require(range.start() == signature.address() && range.end() == signature.address() + 8 &&
                            range.storage() instanceof RegisterRelativeStorage relative &&
                            relative.register().dwarfNumber() == 0 && relative.byteOffset() == 0,
                            "unchanged pointer must describe the object at its address throughout nop/ret");
                        require(DwarfLocationExpression.planStable(variable) instanceof DwarfLocationExpression.Expression expression &&
                            expression.operations().equals(List.of(new DwarfLocationExpression.GenericOperation(
                                DwarfLocationExpression.DW_OP_BREGX, 0, 0))),
                            "formal object location must be bregx, not direct pointer-value regx");
                    }
                }
                case "pointer" -> require(returnType instanceof TypeGraph.IndirectionType pointer &&
                    types.get(pointer.target().key()) instanceof TypeGraph.AggregateType,
                    "genuine pointer return was converted into an aggregate");
                case "scalar" -> require(returnType instanceof TypeGraph.BaseType && returnType.byteSize() == 4,
                    "scalar return changed");
                case "nothing" -> require(returnType instanceof TypeGraph.VoidType, "void return changed");
                case "custom" -> {
                    DataType formal = function.getReturn().getFormalDataType();
                    require(function.hasCustomVariableStorage() && !function.getReturn().isForcedIndirect(),
                        "custom conversion premise differs");
                    require((formal instanceof Pointer && returnType instanceof TypeGraph.IndirectionType) ||
                        (formal instanceof VoidDataType && returnType instanceof TypeGraph.VoidType),
                        "custom conversion must retain the current curated signature");
                    require(signature.parameters().stream().noneMatch(parameter -> parameter.artificial() || parameter.returnStorage()),
                        "materialized custom parameters must not be guessed artificial from their name");
                }
                default -> throw new AssertionError(signature.name());
            }
            require(signature.parameters().get(signature.parameters().size() - 1).name().equals("seed"),
                "explicit parameter order changed");
        }
        require(model.equals(extract(program, target, TaskMonitor.DUMMY)), "unchanged extraction is nondeterministic");
    }

    private static void require(boolean value, String message) {
        checks++;
        if (!value) {
            throw new AssertionError(message);
        }
    }
}
