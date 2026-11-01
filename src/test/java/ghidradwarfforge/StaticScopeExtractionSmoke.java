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
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.types.ProgramTypeModel;

/** Extraction must preserve shadowing while isolating rejected and ambiguous static identities. */
public final class StaticScopeExtractionSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (String[] profile : List.of(new String[] {"x86:LE:64:default", "x86_64"},
                new String[] {"AARCH64:LE:64:v8A", "aarch64"}, new String[] {"ARM:LE:32:v8", "arm"},
                new String[] {"MIPS:BE:32:default", "mips"}, new String[] {"MIPS:LE:32:default", "mipsel"})) {
            check(profile[0], profile[1]);
        }
        System.out.println("static-scope-extraction=PASS checks=" + checks);
    }

    private static void check(String languageId, String target) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(languageId));
        Object token = new Object();
        var program = new ProgramDB("static-scopes", language, language.getDefaultCompilerSpec(), token);
        var directory = Files.createTempDirectory("forge-static-extraction-");
        var saved = directory.resolve("program.db");
        var diagnostics = new ArrayList<String>();
        long entryOffset = languageId.startsWith("MIPS") ? 0x80401000L : 0x401000;
        var symbols = List.of(new FunctionSymbol("scoped", entryOffset, 64));
        ProgramTypeModel expected;
        try {
            int tx = program.startTransaction("static extraction fixture");
            try {
                var entry = language.getDefaultSpace().getAddress(entryOffset);
                program.getMemory().createInitializedBlock("image", entry, 512, (byte) 0, TaskMonitor.DUMMY, false);
                var function = program.getFunctionManager().createFunction("scoped", entry,
                    new AddressSet(entry, entry.add(63)), SourceType.USER_DEFINED);
                function.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
                var namespace = program.getSymbolTable().createNameSpace(program.getGlobalNamespace(), "scoped", SourceType.IMPORTED);
                var blocks = List.of(new GhidraLexicalScopes.Block("outer", "", new AddressSet(entry.add(8), entry.add(31))),
                    new GhidraLexicalScopes.Block("inner", "outer", new AddressSet(entry.add(16), entry.add(23))),
                    new GhidraLexicalScopes.Block("sibling", "", new AddressSet(entry.add(40), entry.add(47))));
                GhidraLexicalScopes.save(function, "saved lexical tree", blocks, List.of(), TaskMonitor.DUMMY);
                var values = new ArrayList<ghidra.program.model.symbol.Symbol>();
                var owners = List.of("", "outer", "inner", "sibling");
                for (int i = 0; i < owners.size(); i++) {
                    var address = entry.add(256 + i * 4);
                    program.getListing().createData(address, IntegerDataType.dataType);
                    var symbol = program.getSymbolTable().createLabel(address, "saved_" + i,
                        i == 0 ? function : namespace, SourceType.USER_DEFINED);
                    symbol.setPrimary();
                    values.add(symbol);
                    GhidraStaticBindings.save(program, symbol, function, owners.get(i), "shadow", "fixture ownership", TaskMonitor.DUMMY);
                }
                program.getListing().createData(entry.add(300), IntegerDataType.dataType);
                program.getSymbolTable().createLabel(entry.add(300), "shadow", SourceType.USER_DEFINED).setPrimary();
                expected = extract(program, symbols, target, 0, diagnostics);
                observe(expected, entryOffset);
                var options = program.getOptions(GhidraStaticBindings.OPTIONS_NAME);
                String innerKey = "static-" + values.get(2).getID();
                String inner = options.getString(innerKey, null);
                options.setString(innerKey, "GDFSB1:!");
                var rejected = extract(program, symbols, target, 0, diagnostics);
                require(rejected.functionStatics().size() == 3 && rejected.globals().size() == 1,
                    "rejected binding cannot reappear as a global or inferred function static");
                require(diagnostics.stream().anyMatch(d -> d.startsWith("Omitted explicit static binding")), "rejected binding diagnosed");
                options.setString(innerKey, inner);
                GhidraStaticBindings.save(program, values.get(3), function, "inner", "shadow", "conflicting spelling", TaskMonitor.DUMMY);
                var conflict = extract(program, symbols, target, 0, diagnostics);
                require(conflict.functionStatics().size() == 2 && conflict.globals().size() == 1,
                    "same-scope collision retires both declarations without global fallback");
                require(diagnostics.stream().filter(d -> d.contains("conflicting declaration")).count() == 2, "both conflicts diagnosed");
                GhidraStaticBindings.save(program, values.get(3), function, "sibling", "shadow", "fixture ownership", TaskMonitor.DUMMY);
                var absentOwner = extract(program, List.of(), target, 0, diagnostics);
                require(absentOwner.functionStatics().isEmpty() && absentOwner.globals().size() == 1, "missing exported owner retains no static");
                require(diagnostics.stream().filter(d -> d.contains("was not exported")).count() == 4, "missing owner diagnosed for all objects");
                String lexical = program.getUsrPropertyManager().getStringPropertyMap(GhidraLexicalScopes.PROPERTY_NAME).getString(entry);
                GhidraLexicalScopes.save(function, "updated lexical assertion", blocks, List.of(), TaskMonitor.DUMMY);
                var changedTree = extract(program, symbols, target, 0, diagnostics);
                require(changedTree.functionStatics().size() == 1 && changedTree.functionStatics().getFirst().block().isEmpty(),
                    "stale lexical associations do not migrate to function root");
                program.getUsrPropertyManager().getStringPropertyMap(GhidraLexicalScopes.PROPERTY_NAME).add(entry, lexical);
                require(extract(program, symbols, target, 0, diagnostics).equals(expected), "restored exact evidence restores extraction");
                var invalid = new ArrayList<>(expected.functionStatics());
                var first = invalid.getFirst();
                invalid.add(first);
                reject(() -> new ProgramTypeModel(expected.types(), expected.functions(), expected.globals(), expected.variableStorage(),
                    invalid, expected.functionDeclarations(), expected.lexicalScopes(), expected.classScopes()));
                var oldSignature = expected.functions().getFirst();
                var parameterCollision = new ProgramTypeModel.FunctionSignature(oldSignature.name(), entryOffset, first.type(),
                    List.of(new ghidradwarfforge.types.TypeGraph.Parameter("shadow", first.type(), false)), List.of(),
                    false, false, "default", "USER_DEFINED");
                var parameterConflicts = ProgramTypeModel.conflictingStatics(List.of(parameterCollision), expected.lexicalScopes(), expected.functionStatics());
                require(parameterConflicts.size() == 1 && parameterConflicts.iterator().next().block().isEmpty(),
                    "parameter conflicts only with root static, not nested shadowing");
                var localSignature = new ProgramTypeModel.FunctionSignature(oldSignature.name(), entryOffset, first.type(), List.of(),
                    List.of(new ProgramTypeModel.LocalVariable("local_saved", 4, first.type(), 0, true, "USER_DEFINED")),
                    false, false, "default", "USER_DEFINED");
                var oldScope = expected.lexicalScopes().getFirst();
                var localScope = new ghidradwarfforge.types.LexicalScopeModel(entryOffset, oldScope.body(), oldScope.blocks(),
                    List.of(new ghidradwarfforge.types.LexicalScopeModel.Local("local_saved", "inner", "shadow")), "fixture");
                var localConflicts = ProgramTypeModel.conflictingStatics(List.of(localSignature), List.of(localScope), expected.functionStatics());
                require(localConflicts.size() == 1 && localConflicts.iterator().next().block().equals("inner"),
                    "scoped local conflicts only with static in the same lexical block");
                var missing = new ProgramTypeModel.FunctionStaticVariable("unknown", entryOffset + 304, 4, first.type(),
                    entryOffset, "fixture", "missing");
                reject(() -> new ProgramTypeModel(expected.types(), expected.functions(), expected.globals(), expected.variableStorage(),
                    List.of(missing), expected.functionDeclarations(), expected.lexicalScopes(), expected.classScopes()));
                program.setImageBase(program.getImageBase().add(0x200000), true);
                require(extract(program, symbols, target, 0x200000, diagnostics).equals(expected), "rebasing preserves exact normalized model");
            }
            finally { program.endTransaction(tx, true); }
            program.getDBHandle().saveAs(saved.toFile(), false, TaskMonitor.DUMMY);
            byte[] before = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(saved));
            var modified = Files.getLastModifiedTime(saved);
            var handle = new DBHandle(saved.toFile());
            Object reopenedToken = new Object();
            ProgramDB reopened = null;
            try {
                reopened = new ProgramDB(handle, OpenMode.IMMUTABLE, TaskMonitor.DUMMY, reopenedToken);
                require(extract(reopened, symbols, target, 0x200000, diagnostics).equals(expected), "immutable reopen retains full extraction");
                require(extract(reopened, symbols, target, 0x200000, diagnostics).equals(expected), "repeated extraction is deterministic");
            }
            finally {
                if (reopened != null) reopened.release(reopenedToken);
                else handle.close();
            }
            require(Arrays.equals(before, MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(saved))) &&
                modified.equals(Files.getLastModifiedTime(saved)), "immutable saved database unchanged");
            System.out.println("static-extraction-target=PASS " + languageId);
        }
        finally {
            program.release(token);
            Files.deleteIfExists(saved);
            Files.deleteIfExists(directory);
        }
    }

    private static ProgramTypeModel extract(Program program, List<FunctionSymbol> symbols, String target,
            long delta, List<String> diagnostics) throws Exception {
        diagnostics.clear();
        return GhidraTypeGraph.extract(program, symbols, target, delta, TaskMonitor.DUMMY, diagnostics::add);
    }

    private static void observe(ProgramTypeModel model, long entry) {
        require(model.functionStatics().size() == 4 && model.globals().size() == 1, "four statics and one independent global");
        require(model.functionStatics().stream().allMatch(v -> v.name().equals("shadow") && v.ownerAddress() == entry), "explicit shadow names and owner");
        require(model.functionStatics().stream().map(ProgramTypeModel.FunctionStaticVariable::block).toList()
            .equals(List.of("", "inner", "outer", "sibling")), "stable scope order");
        require(model.functionStatics().stream().map(ProgramTypeModel.FunctionStaticVariable::address).sorted().toList()
            .equals(List.of(entry + 256, entry + 260, entry + 264, entry + 268)), "distinct physical objects");
    }

    @FunctionalInterface private interface Action { void run() throws Exception; }
    private static void reject(Action action) throws Exception {
        try { action.run(); throw new AssertionError("invalid static scope model accepted"); }
        catch (IllegalArgumentException expected) { checks++; }
    }
    private static void require(boolean value, String message) {
        checks++;
        if (!value) throw new AssertionError(message);
    }
}
