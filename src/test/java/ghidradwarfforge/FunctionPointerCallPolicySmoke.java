package ghidradwarfforge;

import java.io.File;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import db.DBHandle;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.data.OpenMode;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.PointerDataType;
import ghidradwarfforge.types.TypeGraph.SubroutineType;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;

/** Persisted compiler-model identity; no architecture-specific convention whitelist. */
public final class FunctionPointerCallPolicySmoke {
    private record Target(String language, String map) { }
    private record Expected(long entry, String name, String convention, boolean blocked) { }
    private static int checks;

    private FunctionPointerCallPolicySmoke() { }

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (Target target : List.of(
                new Target("x86:LE:64:default", "x86_64"),
                new Target("AARCH64:LE:64:v8A", "aarch64"),
                new Target("ARM:LE:32:v8", "arm"),
                new Target("MIPS:BE:32:default", "mips"),
                new Target("MIPS:LE:32:default", "mipsel"))) {
            check(target);
        }
        System.out.println("function-pointer-call-policy-smoke=PASS checks=" + checks);
    }

    private static void check(Target target) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(target.language()));
        var compiler = target.map().equals("x86_64")
            ? language.getCompilerSpecByID(new CompilerSpecID("gcc")) : language.getDefaultCompilerSpec();
        Object owner = new Object();
        var program = new ProgramDB("conventions", language, compiler, owner);
        var directory = Files.createTempDirectory("forge-convention-policy-");
        var saved = directory.resolve("program.db");
        var expected = new ArrayList<Expected>();
        try {
            int transaction = program.startTransaction("convention controls");
            try {
                var start = language.getDefaultSpace().getAddress(0x1000);
                program.getMemory().createInitializedBlock("code", start, 0x10000,
                    (byte) 0, TaskMonitor.DUMMY, false);
                String defaultName = compiler.getDefaultCallingConvention().getName();
                var names = new ArrayList<String>();
                names.add(Function.UNKNOWN_CALLING_CONVENTION_STRING);
                names.add(Function.DEFAULT_CALLING_CONVENTION_STRING);
                for (var convention : compiler.getCallingConventions()) {
                    if (!names.contains(convention.getName())) {
                        names.add(convention.getName());
                    }
                }
                require(names.contains(defaultName), "default model is missing");
                for (String convention : names) {
                    long entry = 0x1000 + expected.size() * 0x20;
                    String name = "function_" + expected.size();
                    boolean blocked = !convention.equals(defaultName) &&
                        !convention.equals(Function.DEFAULT_CALLING_CONVENTION_STRING);
                    var address = language.getDefaultSpace().getAddress(entry);
                    var functionType = new FunctionDefinitionDataType("callback_" + expected.size(),
                        program.getDataTypeManager());
                    functionType.setReturnType(IntegerDataType.dataType);
                    functionType.setArguments(new ParameterDefinitionImpl("value", IntegerDataType.dataType, ""));
                    functionType.setCallingConvention(convention);
                    program.getListing().createData(address, new PointerDataType(functionType, program.getDataTypeManager()));
                    program.getSymbolTable().createLabel(address, name, SourceType.USER_DEFINED);
                    expected.add(new Expected(entry, name, convention, blocked));
                }
                observe(program, target, expected);
            }
            finally {
                program.endTransaction(transaction, true);
            }
            program.getDBHandle().saveAs(saved.toFile(), false, TaskMonitor.DUMMY);
            byte[] before = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(saved));
            var mtime = Files.getLastModifiedTime(saved);
            Object reopenedOwner = new Object();
            DBHandle handle = new DBHandle(saved.toFile());
            ProgramDB reopened = null;
            try {
                reopened = new ProgramDB(handle, OpenMode.IMMUTABLE, TaskMonitor.DUMMY, reopenedOwner);
                observe(reopened, target, expected);
            }
            finally {
                if (reopened != null) {
                    reopened.release(reopenedOwner);
                }
                else {
                    handle.close();
                }
            }
            require(Arrays.equals(before, MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(saved))) &&
                mtime.equals(Files.getLastModifiedTime(saved)), "immutable database changed");
            System.out.println("function-pointer-call-policy-target=PASS " + target.language() +
                " models=" + expected.size() + " blocked=" + expected.stream().filter(Expected::blocked).count());
        }
        finally {
            program.release(owner);
            Files.deleteIfExists(saved);
            Files.deleteIfExists(directory);
        }
    }

    private static void observe(ProgramDB program, Target target, List<Expected> expected) throws Exception {
        var diagnostics = new ArrayList<String>();
        var model = GhidraTypeGraph.extract(program, List.of(), target.map(), 0, TaskMonitor.DUMMY, diagnostics::add);
        require(model.functions().isEmpty() && model.functionDeclarations().isEmpty(), "invented callable definition");
        var subroutines = model.types().nodes().stream().filter(n -> n instanceof SubroutineType)
            .map(n -> (SubroutineType) n).toList();
        require(subroutines.size() == expected.size(), "function-pointer multiplicity changed");
        for (int index = 0; index < expected.size(); index++) {
            var row = expected.get(index);
            String name = "callback_" + index;
            var type = subroutines.stream().filter(n -> n.name().equals(name)).findFirst().orElseThrow();
            require(type.callingConvention().equals(row.convention()), "recorded convention lost: " + row);
            require(type.debuggerCallsDisabled() == row.blocked(), "function-pointer decision differs: " + row);
            require(type.parameters().size() == 1 && type.parameters().get(0).name().equals("value"),
                "formal parameter lost");
            require(type.returnType().equals(type.parameters().get(0).type()), "return/parameter types differ");
            require(type.restrictDebuggerCalls("extra").restrictDebuggerCalls("extra").equals(
                type.restrictDebuggerCalls("extra")), "duplicate restriction");
            require(type.restrictDebuggerCalls("") == type, "empty restriction changes type");
        }
        require(diagnostics.stream().filter(s -> s.startsWith("Debugger-injected calls disabled for function type ")).count() ==
            expected.stream().filter(Expected::blocked).count(), "diagnostic multiplicity differs");
        var repeatedDiagnostics = new ArrayList<String>();
        require(model.equals(GhidraTypeGraph.extract(program, List.of(), target.map(), 0, TaskMonitor.DUMMY,
            repeatedDiagnostics::add)) && diagnostics.equals(repeatedDiagnostics), "extraction is not deterministic");
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
