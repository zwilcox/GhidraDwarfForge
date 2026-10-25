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
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.TypeGraph;

/** Scalar evidence policy, provenance precedence, address normalization and immutable reopen. */
public final class RecoveredReturnSmoke {
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
        System.out.println("recovered-return-smoke=PASS checks=" + checks);
    }

    private static void check(Target target) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(target.language()));
        var compiler = target.map().equals("x86_64")
            ? language.getCompilerSpecByID(new CompilerSpecID("gcc")) : language.getDefaultCompilerSpec();
        Object owner = new Object();
        var program = new ProgramDB("recovered-returns", language, compiler, owner);
        var directory = Files.createTempDirectory("forge-recovered-returns-");
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
            System.out.println("recovered-return-target=PASS " + target.language());
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

    private static ProgramTypeModel extract(ProgramDB program, Target target, Map<Long, DataType> returns,
            TaskMonitor monitor, List<String> diagnostics) throws Exception {
        var symbols = new ArrayList<FunctionSymbol>();
        for (Function function : program.getFunctionManager().getFunctions(true)) {
            symbols.add(new FunctionSymbol(function.getName(), function.getEntryPoint().getOffset() - 0x800,
                function.getBody().getNumAddresses()));
        }
        return GhidraTypeGraph.extract(program, symbols, target.map(), 0x800, monitor, diagnostics::add, returns);
    }

    private static TypeGraph.TypeNode returned(ProgramTypeModel model, String name) {
        var signature = model.functions().stream().filter(f -> f.name().equals(name)).findFirst().orElseThrow();
        return model.types().byKey().get(signature.returnType().key());
    }

    private static void observe(ProgramDB program, Target target) throws Exception {
        var unknown = program.getFunctionManager().getFunctionAt(
            program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000));
        require(unknown.getSignatureSource() == SourceType.DEFAULT &&
            unknown.getReturn().getSource() == SourceType.DEFAULT &&
            Undefined.isUndefined(unknown.getReturn().getFormalDataType()), "unknown signature premise");
        var baseline = extract(program, target, Map.of(), TaskMonitor.DUMMY, new ArrayList<>());
        require(returned(baseline, "unknown") instanceof TypeGraph.OpaqueType, "missing evidence must remain unknown");
        for (DataType candidate : List.of(IntegerDataType.dataType, UnsignedIntegerDataType.dataType,
                FloatDataType.dataType, DoubleDataType.dataType, BooleanDataType.dataType)) {
            var evidence = Map.of(0x800L, candidate, 0x900L, candidate, 0xa00L, candidate,
                0xb00L, candidate, 0xc00L, candidate, 0xd00L, candidate);
            var diagnostics = new ArrayList<String>();
            var model = extract(program, target, evidence, TaskMonitor.DUMMY, diagnostics);
            require(returned(model, "unknown") instanceof TypeGraph.BaseType type &&
                type.byteSize() == candidate.getLength(), "concrete scalar evidence lost");
            require(model.functions().stream().filter(f -> f.name().equals("unknown")).findFirst().orElseThrow()
                .signatureSource().equals("DEFAULT"), "recovered return mislabeled as curated signature");
            for (String name : List.of("USER_DEFINED", "IMPORTED", "ANALYSIS", "custom", "pointer")) {
                require(returned(model, name).equals(returned(baseline, name)), "overrode stronger/unsupported signature " + name);
            }
            require(model.variableStorage().equals(baseline.variableStorage()), "return recovery fabricated locations");
            require(diagnostics.stream().filter(d -> d.startsWith("Using decompiler-recovered scalar return")).count() == 1,
                "missing or excessive return provenance diagnostic");
            require(model.equals(extract(program, target, evidence, TaskMonitor.DUMMY, new ArrayList<>())),
                "repeated extraction changed");
        }
        for (DataType rejected : List.of(Undefined4DataType.dataType, DataType.DEFAULT, VoidDataType.dataType,
                new PointerDataType(IntegerDataType.dataType), new StructureDataType("Unproven", 16))) {
            require(extract(program, target, Map.of(0x800L, rejected), TaskMonitor.DUMMY, new ArrayList<>()).equals(baseline),
                "unsupported return evidence changed model: " + rejected);
        }
        require(!GhidraTypeGraph.acceptRecoveredReturn(unknown, null), "absent evidence accepted");
        require(extract(program, target, Map.of(0x1000L, IntegerDataType.dataType), TaskMonitor.DUMMY,
            new ArrayList<>()).equals(baseline), "evidence used wrong address coordinate system");
        var cancelled = new TaskMonitorAdapter(true);
        cancelled.cancel();
        try {
            extract(program, target, Map.of(0x800L, IntegerDataType.dataType), cancelled, new ArrayList<>());
            throw new AssertionError("ignored cancellation");
        }
        catch (CancelledException expected) {
            checks++;
        }
        require(unknown.getSignatureSource() == SourceType.DEFAULT &&
            unknown.getReturn().getSource() == SourceType.DEFAULT &&
            Undefined.isUndefined(unknown.getReturn().getFormalDataType()), "recovery modified saved signature");
    }

    private static void require(boolean value, String message) {
        checks++;
        if (!value) {
            throw new AssertionError(message);
        }
    }
}
