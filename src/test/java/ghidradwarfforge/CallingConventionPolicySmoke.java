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
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;

/** Persisted compiler-model identity; no architecture-specific convention whitelist. */
public final class CallingConventionPolicySmoke {
    private record Target(String language, String map) { }
    private record Expected(long entry, String name, String convention, boolean blocked) { }
    private static int checks;

    private CallingConventionPolicySmoke() { }

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
        System.out.println("calling-convention-policy-smoke=PASS checks=" + checks);
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
                        !convention.equals(Function.UNKNOWN_CALLING_CONVENTION_STRING) &&
                        !convention.equals(Function.DEFAULT_CALLING_CONVENTION_STRING);
                    var address = language.getDefaultSpace().getAddress(entry);
                    Function function = program.getFunctionManager().createFunction(name, address,
                        new AddressSet(address, address.add(3)), SourceType.USER_DEFINED);
                    prepare(function, convention);
                    Function external = program.getExternalManager().addExtFunction("library", name,
                        null, SourceType.USER_DEFINED).getFunction();
                    prepare(external, convention);
                    expected.add(new Expected(entry, name, convention, blocked));
                }
                // Custom storage with an unknown model is no longer implicitly callable.
                var first = program.getFunctionManager().getFunctionAt(start);
                first.setCustomVariableStorage(true);
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
            System.out.println("calling-convention-policy-target=PASS " + target.language() +
                " models=" + expected.size() + " blocked=" + expected.stream().filter(Expected::blocked).count());
        }
        finally {
            program.release(owner);
            Files.deleteIfExists(saved);
            Files.deleteIfExists(directory);
        }
    }

    private static void prepare(Function function, String convention) throws Exception {
        function.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
        function.setCallingConvention(convention);
        function.setSignatureSource(SourceType.USER_DEFINED);
    }

    private static void observe(ProgramDB program, Target target, List<Expected> expected) throws Exception {
        var symbols = expected.stream().map(row -> new FunctionSymbol(row.name(), row.entry(), 4)).toList();
        var diagnostics = new ArrayList<String>();
        var model = GhidraTypeGraph.extract(program, symbols, target.map(), 0, TaskMonitor.DUMMY, diagnostics::add);
        require(model.functions().size() == expected.size() &&
            model.functionDeclarations().size() == expected.size(), "signature multiplicity changed");
        for (Expected row : expected) {
            var signature = model.functions().stream().filter(f -> f.address() == row.entry()).findFirst().orElseThrow();
            var declaration = model.functionDeclarations().stream()
                .filter(f -> f.name().equals("library::" + row.name())).findFirst().orElseThrow();
            require(signature.callingConvention().equals(row.convention()) &&
                signature.nonDefaultCallingConvention() == row.blocked(), "definition policy differs: " + row);
            require(declaration.callingConvention().equals(row.convention()) &&
                declaration.nonDefaultCallingConvention() == row.blocked(), "declaration policy differs: " + row);
            require(signature.signatureSource().equals("USER_DEFINED") &&
                declaration.signatureSource().equals("USER_DEFINED"), "signature provenance lost");
            var actual = program.getFunctionManager().getFunctionAt(program.getAddressFactory()
                .getDefaultAddressSpace().getAddress(row.entry()));
            String resolved = actual.getCallingConvention() == null ? "" : actual.getCallingConvention().getName();
            String fallback = program.getCompilerSpec().getDefaultCallingConvention().getName();
            require(signature.effectiveCallingConvention().equals(resolved),
                "custom unknown convention acquired a fallback, or resolved convention lost");
            require(declaration.effectiveCallingConvention().equals(
                row.convention().equals(Function.UNKNOWN_CALLING_CONVENTION_STRING) ? fallback : resolved),
                "dynamic external default model lost");
        }
        require(diagnostics.stream().filter(s -> s.startsWith("Calling convention requires target ABI classification for ")).count() ==
            2 * expected.stream().filter(Expected::blocked).count(), "unmapped convention diagnostic multiplicity differs");
        require(diagnostics.stream().filter(s -> s.startsWith("Debugger-injected calls disabled for ")).count() == 1,
            "independent custom restriction diagnostic multiplicity differs");
        var unknownCustom = model.functions().stream().filter(f -> f.address() == expected.get(0).entry())
            .findFirst().orElseThrow();
        require(unknownCustom.debuggerCallsDisabled() && !unknownCustom.nonDefaultCallingConvention() &&
            unknownCustom.debuggerCallRestriction().contains("resolved default"), "unknown custom call remains enabled");
        var repeatedDiagnostics = new ArrayList<String>();
        require(model.equals(GhidraTypeGraph.extract(program, symbols, target.map(), 0, TaskMonitor.DUMMY,
            repeatedDiagnostics::add)) && diagnostics.equals(repeatedDiagnostics), "extraction is not deterministic");
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
