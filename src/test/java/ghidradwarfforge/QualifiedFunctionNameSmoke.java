package ghidradwarfforge;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.source.SyntheticSourceFile;
import ghidradwarfforge.source.SyntheticSourceFile.FunctionText;

/** Actual Ghidra scope extraction; no native producer or decompiler is loaded. */
public final class QualifiedFunctionNameSmoke {
    private QualifiedFunctionNameSmoke() {
    }

    public static void main(String[] args) throws Exception {
        modelControls();
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        var language = DefaultLanguageService.getLanguageService().getLanguage(
            new LanguageID("x86:LE:64:default"));
        Object consumer = new Object();
        var program = new ProgramDB("qualified-functions", language,
            language.getDefaultCompilerSpec(), consumer);
        try {
            checkProgram(program);
        }
        finally {
            program.release(consumer);
        }
        System.out.println("qualified-function-name-smoke=PASS");
    }

    private static void modelControls() throws Exception {
        var legacy = new FunctionSymbol("literal::legacy", 0x1000, 8);
        require(legacy.namespacePath().isEmpty() &&
            legacy.qualifiedDisplayName().equals(legacy.name()), "legacy name changed");
        var path = new ArrayList<>(List.of("left", "nested"));
        var qualified = new FunctionSymbol("same_name", 0x2000,
            List.of(new FunctionRange(0x2000, 8)), path);
        path.clear();
        require(qualified.name().equals("same_name") &&
            qualified.qualifiedDisplayName().equals("left::nested::same_name"),
            "display path changed lexical identity or retained a mutable input");
        try {
            qualified.namespacePath().add("mutated");
            throw new AssertionError("namespace path is mutable");
        }
        catch (UnsupportedOperationException expected) {
            // Immutable model contract.
        }
        var duplicate = new FunctionSymbol("same_name", 0x2100,
            List.of(new FunctionRange(0x2100, 8)), List.of("left", "nested"));
        FunctionSymbol.validateDisplayNames(List.of(qualified, duplicate, legacy));
        collision(qualified, new FunctionSymbol("left::nested::same_name", 0x2200, 8));
        collision(qualified, new FunctionSymbol("same_name", 0x2200,
            List.of(new FunctionRange(0x2200, 8)), List.of("left::nested")));
        collision(qualified, new FunctionSymbol("nested::same_name", 0x2200,
            List.of(new FunctionRange(0x2200, 8)), List.of("left")));
        publicExportRejects(qualified,
            new FunctionSymbol("left::nested::same_name", 0x2200, 8));
        reject(() -> new FunctionSymbol("same_name", 0x2000,
            List.of(new FunctionRange(0x2000, 8)), List.of("")),
            "invalid function namespace path");
        reject(() -> new FunctionSymbol("same_name", 0x2000,
            List.of(new FunctionRange(0x2000, 8)), null), "invalid function namespace path");

        var source = SyntheticSourceFile.build("fixture", "x86:LE:64:default", List.of(
            new FunctionText(qualified.name(), qualified.address(),
                "int same_name(void)\n{\n    return 37;\n}\n", null)));
        require(source.functions().get(0).name().equals("same_name") &&
            source.mappedLines().get(0).addresses().equals(List.of(qualified.address())) &&
            source.mappedLines().get(0).line() == source.functions().get(0).startLine(),
            "qualified display lost the lexical declaration/entry line");
    }

    private static void publicExportRejects(FunctionSymbol first, FunctionSymbol second)
            throws Exception {
        var directory = Files.createTempDirectory("forge-qualified-collision-");
        var output = directory.resolve("preserved.dbg");
        var original = directory.resolve("invalid-original");
        var consumer = directory.resolve("invalid-consumer");
        var producer = directory.resolve("invalid-producer");
        var files = List.of(output, original, consumer, producer);
        byte[] sentinel = new byte[] { 7, 3, 9, 1 };
        for (var file : files) {
            Files.write(file, sentinel);
        }
        try {
            // Regular files satisfy the existing file preflight. Invalid bytes
            // prove collision rejection precedes ELF parsing or native loading.
            reject(() -> new MinimalDwarfSidecarExporter().export(original, output, consumer, producer,
                List.of(first, second)), "ambiguous qualified function display name");
            for (var file : files) {
                require(Arrays.equals(Files.readAllBytes(file), sentinel),
                    "rejected collision changed an input or the existing destination");
            }
            try (var entries = Files.list(directory)) {
                require(Set.copyOf(entries.toList()).equals(Set.copyOf(files)),
                    "rejected collision left temporary files");
            }
        }
        finally {
            for (var file : files) {
                Files.deleteIfExists(file);
            }
            Files.delete(directory);
        }
    }

    private static void checkProgram(ProgramDB program) throws Exception {
        int transaction = program.startTransaction("curate namespace controls");
        try {
            var symbols = program.getSymbolTable();
            Namespace global = program.getGlobalNamespace();
            Namespace left = symbols.createNameSpace(global, "left", SourceType.USER_DEFINED);
            Namespace leftNested = symbols.createNameSpace(left, "nested",
                SourceType.USER_DEFINED);
            Namespace right = symbols.createNameSpace(global, "right", SourceType.USER_DEFINED);
            Namespace rightNested = symbols.createNameSpace(right, "nested",
                SourceType.USER_DEFINED);
            var start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x400000);
            program.getMemory().createInitializedBlock("code", start, 0x1000, (byte) 0,
                TaskMonitor.DUMMY, false);
            Function ordinary = function(program, "ordinary", global, 0x400000);
            function(program, "same_name", leftNested, 0x400100);
            function(program, "same_name", rightNested, 0x400200);
            // Plain scopes under a class must not be mistaken for an all-plain path.
            Namespace type = symbols.createClass(global, "AnalystClass", SourceType.USER_DEFINED);
            Namespace classNested = symbols.createNameSpace(type, "nested", SourceType.USER_DEFINED);
            function(program, "class_method", classNested, 0x400300);
            Namespace library = symbols.createExternalLibrary("libfixture", SourceType.USER_DEFINED);
            require(!SymbolType.FUNCTION.isValidParent(program, library, start, false) &&
                !SymbolType.FUNCTION.isValidParent(program, ordinary, start, false),
                "pinned API unexpectedly permits internal function/library ownership");

            var diagnostics = new ArrayList<String>();
            var first = GhidraFunctionSymbols.extractDetailed(program, TaskMonitor.DUMMY,
                diagnostics::add, 0x1000);
            require(first.skippedFunctions().isEmpty() && first.functions().size() == 4,
                "real functions were skipped");
            require(first.functions().equals(GhidraFunctionSymbols.extract(program,
                TaskMonitor.DUMMY, ignored -> { }, 0x1000)), "extraction is not deterministic");
            FunctionSymbol extracted = at(first.functions(), 0x3ff100);
            require(extracted.name().equals("same_name") &&
                extracted.namespacePath().equals(List.of("left", "nested")) &&
                extracted.qualifiedDisplayName().equals("left::nested::same_name") &&
                extracted.ranges().equals(List.of(new FunctionRange(0x3ff100, 16))),
                "nested identity changed lexical name, body or rebase normalization");
            require(at(first.functions(), 0x3ff200).qualifiedDisplayName()
                .equals("right::nested::same_name"), "duplicate short names collapsed");
            require(at(first.functions(), 0x3ff000).qualifiedDisplayName().equals("ordinary"),
                "ordinary function display changed");
            require(at(first.functions(), 0x3ff300).namespacePath().isEmpty() &&
                at(first.functions(), 0x3ff300).qualifiedDisplayName().equals("class_method") &&
                diagnostics.size() == 1 && diagnostics.get(0).contains("Class scope is unsupported"),
                "unsupported class scope was guessed or silently discarded");

            // Ghidra accepts both forms as distinct symbols. The flat display is
            // ambiguous, so extraction must reject instead of renaming either.
            function(program, "left::nested::same_name", global, 0x400400);
            reject(() -> GhidraFunctionSymbols.extract(program, TaskMonitor.DUMMY,
                ignored -> { }, 0), "ambiguous qualified function display name");
            program.getFunctionManager().removeFunction(start.add(0x400));
            Namespace literal = symbols.createNameSpace(global, "left::nested",
                SourceType.USER_DEFINED);
            function(program, "same_name", literal, 0x400500);
            reject(() -> GhidraFunctionSymbols.extract(program, TaskMonitor.DUMMY,
                ignored -> { }, 0), "ambiguous qualified function display name");
        }
        finally {
            program.endTransaction(transaction, false);
        }
    }

    private static Function function(ProgramDB program, String name, Namespace scope,
            long offset) throws Exception {
        var entry = program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
        return program.getFunctionManager().createFunction(name, scope, entry,
            new AddressSet(entry, entry.add(15)), SourceType.USER_DEFINED);
    }

    private static FunctionSymbol at(List<FunctionSymbol> functions, long address) {
        return functions.stream().filter(function -> function.address() == address)
            .findFirst().orElseThrow();
    }

    private static void collision(FunctionSymbol first, FunctionSymbol second) {
        reject(() -> FunctionSymbol.validateDisplayNames(List.of(first, second)),
            "ambiguous qualified function display name");
    }

    private static void reject(CheckedAction action, String message) {
        try {
            action.run();
            throw new AssertionError("expected rejection: " + message);
        }
        catch (IllegalArgumentException expected) {
            require(expected.getMessage().contains(message), "unexpected rejection: " + expected);
        }
        catch (Exception unexpected) {
            throw new AssertionError("unexpected failure", unexpected);
        }
    }

    @FunctionalInterface
    private interface CheckedAction {
        void run() throws Exception;
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
