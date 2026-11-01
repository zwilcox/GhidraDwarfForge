package ghidradwarfforge;

import java.io.File;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import db.DBHandle;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.data.OpenMode;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.GhidraLexicalScopes.Block;
import ghidradwarfforge.GhidraLexicalScopes.Local;

/** Real saved identities and rebasing, independent of any machine-location proof. */
public final class LexicalScopeEvidenceSmoke {
    private static int checks;
    private static final String MAP = GhidraLexicalScopes.PROPERTY_NAME;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (String language : List.of("x86:LE:64:default", "AARCH64:LE:64:v8A",
                "ARM:LE:32:v8", "MIPS:BE:32:default", "MIPS:LE:32:default")) check(language);
        System.out.println("lexical-scope-evidence-smoke=PASS checks=" + checks);
    }

    private static void check(String languageId) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(languageId));
        Object owner = new Object();
        var program = new ProgramDB("lexical-evidence", language, language.getDefaultCompilerSpec(), owner);
        var directory = Files.createTempDirectory("forge-lexical-evidence-");
        var saved = directory.resolve("program.db");
        long entryOffset = languageId.startsWith("MIPS") ? 0x80401000L : 0x401000;
        long rebasedOffset;
        try {
            int tx = program.startTransaction("lexical evidence controls");
            try {
                var entry = language.getDefaultSpace().getAddress(entryOffset);
                program.getMemory().createInitializedBlock("body", entry.subtract(16), 256, (byte) 0, TaskMonitor.DUMMY, false);
                var body = new AddressSet(entry.subtract(16), entry.add(31));
                body.add(entry.add(40), entry.add(63));
                var function = program.getFunctionManager().createFunction("scoped", entry, body, SourceType.USER_DEFINED);
                function.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true,
                    SourceType.USER_DEFINED, new ParameterImpl("parameter", IntegerDataType.dataType, program));
                var outer = function.addLocalVariable(new LocalVariableImpl("shadow", IntegerDataType.dataType,
                    -16, program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
                var inner = function.addLocalVariable(new LocalVariableImpl("shadow_1", IntegerDataType.dataType,
                    -32, program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
                var other = program.getFunctionManager().createFunction("other", entry.add(80),
                    new AddressSet(entry.add(80), entry.add(95)), SourceType.USER_DEFINED);
                var foreign = other.addLocalVariable(new LocalVariableImpl("foreign", IntegerDataType.dataType,
                    -16, program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
                var diagnostics = new ArrayList<String>();
                require(GhidraLexicalScopes.read(function, TaskMonitor.DUMMY, diagnostics::add).isEmpty() && diagnostics.isEmpty(),
                    "absence does not invent scopes");
                require(program.getUsrPropertyManager().getStringPropertyMap(MAP) == null, "read does not create map");
                var innerBody = new AddressSet(entry.add(8), entry.add(15));
                innerBody.add(entry.add(40), entry.add(47));
                var parent = new Block("outer", "", body);
                var child = new Block("inner", "outer", innerBody);
                var negative = new Block("before-entry", "outer", new AddressSet(entry.subtract(16), entry.subtract(1)));
                var blocks = List.of(child, negative, parent);
                var locals = List.of(new Local(inner, "inner", "shadow"), new Local(outer, "outer", "shadow"));
                GhidraLexicalScopes.save(function, "analyst-recorded lexical ownership", blocks, locals, TaskMonitor.DUMMY);
                var properties = program.getUsrPropertyManager().getStringPropertyMap(MAP);
                String original = properties.getString(entry);
                observe(function);
                require(!original.contains("shadow"), "bounded binary envelope is used");
                GhidraLexicalScopes.save(function, "analyst-recorded lexical ownership", List.of(parent, child, negative),
                    List.of(locals.get(1), locals.get(0)), TaskMonitor.DUMMY);
                require(properties.getString(entry).equals(original), "order-independent deterministic encoding");
                innerBody.clear();
                ((AddressSet) child.body()).clear();
                require(child.body().getNumAddressRanges() == 2, "defensive address-set ownership");
                reject(() -> GhidraLexicalScopes.save(function, "test", List.of(parent, parent), locals, TaskMonitor.DUMMY));
                reject(() -> GhidraLexicalScopes.save(function, "test", List.of(new Block("x", "missing", body)), List.of(), TaskMonitor.DUMMY));
                reject(() -> GhidraLexicalScopes.save(function, "test", List.of(new Block("a", "b", body), new Block("b", "a", body)), List.of(), TaskMonitor.DUMMY));
                reject(() -> GhidraLexicalScopes.save(function, "test", List.of(parent, new Block("x", "", body)), List.of(), TaskMonitor.DUMMY));
                reject(() -> GhidraLexicalScopes.save(function, "test", List.of(new Block("x", "", new AddressSet(entry.add(32), entry.add(39)))), List.of(), TaskMonitor.DUMMY));
                reject(() -> GhidraLexicalScopes.save(function, "test", List.of(child, new Block("outer", "", new AddressSet(entry, entry.add(10)))), List.of(), TaskMonitor.DUMMY));
                reject(() -> GhidraLexicalScopes.save(function, "test", blocks, List.of(new Local(foreign, "inner", "shadow")), TaskMonitor.DUMMY));
                reject(() -> GhidraLexicalScopes.save(function, "test", blocks, List.of(locals.getFirst(), locals.getFirst()), TaskMonitor.DUMMY));
                reject(() -> GhidraLexicalScopes.save(function, "test", blocks, List.of(new Local(inner, "", "shadow")), TaskMonitor.DUMMY));
                reject(() -> GhidraLexicalScopes.save(function, "test", blocks, List.of(new Local(inner, "", "parameter")), TaskMonitor.DUMMY));
                require(properties.getString(entry).equals(original), "failed writes preserve existing evidence");
                inner.setName("renamed", SourceType.USER_DEFINED);
                omitted(function, "name change");
                inner.setName("shadow_1", SourceType.USER_DEFINED);
                inner.setDataType(UnsignedIntegerDataType.dataType, SourceType.USER_DEFINED);
                omitted(function, "same-width different type");
                inner.setDataType(IntegerDataType.dataType, SourceType.USER_DEFINED);
                observe(function);
                ((ghidra.program.model.listing.LocalVariable) inner).setFirstUseOffset(8);
                omitted(function, "first-use identity change");
                ((ghidra.program.model.listing.LocalVariable) inner).setFirstUseOffset(0);
                observe(function);
                var trimmed = new AddressSet(body);
                trimmed.deleteRange(entry.add(40), entry.add(47));
                function.setBody(trimmed);
                omitted(function, "body changes");
                function.setBody(body);
                properties.add(other.getEntryPoint(), original);
                omitted(other, "record transplanted to another function");
                var malformed = new ArrayList<String>(List.of("bad-prefix", "GDFLS1:%%%%", "GDFLS1:AA==", original + "AA=="));
                byte[] bytes = Base64.getDecoder().decode(original.substring(7));
                var countInput = new java.io.DataInputStream(new java.io.ByteArrayInputStream(bytes));
                countInput.readInt();
                countInput.readLong();
                countInput.readUTF();
                int countOffset = bytes.length - countInput.available();
                for (int badCount : new int[] { -1, Integer.MAX_VALUE }) {
                    byte[] invalidCount = bytes.clone();
                    java.nio.ByteBuffer.wrap(invalidCount).putInt(countOffset, badCount);
                    malformed.add("GDFLS1:" + Base64.getEncoder().encodeToString(invalidCount));
                }
                byte[] trailing = Arrays.copyOf(bytes, bytes.length + 1);
                malformed.add("GDFLS1:" + Base64.getEncoder().encodeToString(trailing));
                byte[] version = bytes.clone();
                version[3] = 2;
                malformed.add("GDFLS1:" + Base64.getEncoder().encodeToString(version));
                for (String corrupt : malformed) {
                    properties.add(entry, corrupt);
                    omitted(function, "malformed envelope");
                    require(properties.getString(entry).equals(corrupt), "read is non-mutating even on corruption");
                }
                properties.add(entry, original);
                var cancelled = new TaskMonitorAdapter(true);
                cancelled.cancel();
                try {
                    GhidraLexicalScopes.read(function, cancelled, diagnostics::add);
                    throw new AssertionError("read ignored cancellation");
                }
                catch (CancelledException expected) { checks++; }
                try {
                    GhidraLexicalScopes.save(function, "cancel", blocks, locals, cancelled);
                    throw new AssertionError("save ignored cancellation");
                }
                catch (CancelledException expected) { checks++; }
                require(properties.getString(entry).equals(original), "cancellation retains record");
                for (boolean writing : new boolean[] { false, true }) {
                    var midway = new TaskMonitorAdapter(true) {
                        private int visits;
                        @Override public void checkCancelled() throws CancelledException {
                            if (++visits == 5) throw new CancelledException();
                        }
                    };
                    try {
                        if (writing) GhidraLexicalScopes.save(function, "cancel mid-record", blocks, locals, midway);
                        else GhidraLexicalScopes.read(function, midway, diagnostics::add);
                        throw new AssertionError("mid-record cancellation ignored");
                    }
                    catch (CancelledException expected) { checks++; }
                    require(properties.getString(entry).equals(original), "mid-record cancellation preserves evidence");
                }
                var oldBase = program.getImageBase();
                program.setImageBase(oldBase.add(0x200000), true);
                rebasedOffset = entryOffset + 0x200000;
                var rebased = program.getFunctionManager().getFunctionAt(language.getDefaultSpace().getAddress(rebasedOffset));
                require(rebased != null, "rebased function exists");
                require(properties.getString(rebased.getEntryPoint()).equals(original), "property anchor follows rebase without payload rewrite");
                observe(rebased);
                var manager = program.getUsrPropertyManager();
                manager.removePropertyMap(MAP);
                var wrongType = manager.createIntPropertyMap(MAP);
                wrongType.add(rebased.getEntryPoint(), 27);
                omitted(rebased, "incompatible property map type");
                reject(() -> GhidraLexicalScopes.save(rebased, "wrong type", List.of(), List.of(), TaskMonitor.DUMMY));
                require(wrongType.getInt(rebased.getEntryPoint()) == 27, "foreign property map is preserved");
                manager.removePropertyMap(MAP);
                manager.createStringPropertyMap(MAP).add(rebased.getEntryPoint(), original);
                observe(rebased);
            }
            finally { program.endTransaction(tx, true); }
            program.getDBHandle().saveAs(saved.toFile(), false, TaskMonitor.DUMMY);
            byte[] before = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(saved));
            var modified = Files.getLastModifiedTime(saved);
            var handle = new DBHandle(saved.toFile());
            Object reopenedOwner = new Object();
            ProgramDB reopened = null;
            try {
                reopened = new ProgramDB(handle, OpenMode.IMMUTABLE, TaskMonitor.DUMMY, reopenedOwner);
                observe(reopened.getFunctionManager().getFunctionAt(language.getDefaultSpace().getAddress(rebasedOffset)));
            }
            finally {
                if (reopened != null) reopened.release(reopenedOwner);
                else handle.close();
            }
            require(Arrays.equals(before, MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(saved))) &&
                modified.equals(Files.getLastModifiedTime(saved)), "immutable saved database unchanged");
            System.out.println("lexical-evidence-target=PASS " + languageId);
        }
        finally {
            program.release(owner);
            Files.deleteIfExists(saved);
            Files.deleteIfExists(directory);
        }
    }

    private static void observe(Function function) throws Exception {
        var diagnostics = new ArrayList<String>();
        var scope = GhidraLexicalScopes.read(function, TaskMonitor.DUMMY, diagnostics::add).orElseThrow(() -> new AssertionError(diagnostics));
        require(diagnostics.isEmpty() && scope.functionId() == function.getSymbol().getID(), "saved function identity");
        require(scope.blocks().stream().map(Block::id).toList().equals(List.of("outer", "before-entry", "inner")), "deterministic parent-first tree");
        require(scope.locals().size() == 2 && scope.locals().stream().allMatch(local -> local.displayName().equals("shadow")), "explicit shadow spelling");
        require(scope.locals().stream().map(local -> local.variable().getName()).sorted().toList().equals(List.of("shadow", "shadow_1")), "listing names unchanged");
        var inner = scope.blocks().getLast();
        require(inner.body().getNumAddressRanges() == 2 && inner.body().getMinAddress().equals(function.getEntryPoint().add(8)) &&
            inner.body().getMaxAddress().equals(function.getEntryPoint().add(47)), "discontiguous rebased ranges");
        require(scope.blocks().get(1).body().getMinAddress().equals(function.getEntryPoint().subtract(16)), "below-entry ranges");
    }

    private static void omitted(Function function, String name) throws Exception {
        var diagnostics = new ArrayList<String>();
        require(GhidraLexicalScopes.read(function, TaskMonitor.DUMMY, diagnostics::add).isEmpty() && diagnostics.size() == 1,
            "stale evidence diagnosed: " + name + diagnostics);
    }

    @FunctionalInterface
    private interface Action { void run() throws Exception; }

    private static void reject(Action action) throws Exception {
        try { action.run(); throw new AssertionError("invalid lexical assertion accepted"); }
        catch (IllegalArgumentException expected) { checks++; }
    }

    private static void require(boolean value, String message) {
        checks++;
        if (!value) throw new AssertionError(message);
    }
}
