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
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.GhidraStaticBindings.Status;

/** Current ProgramDB identities; never infer a function from a namespace spelling. */
public final class StaticBindingEvidenceSmoke {
    private static int checks;
    private static final String GROUP = GhidraStaticBindings.OPTIONS_NAME;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (String language : List.of("x86:LE:64:default", "AARCH64:LE:64:v8A", "ARM:LE:32:v8",
                "MIPS:BE:32:default", "MIPS:LE:32:default")) check(language);
        System.out.println("static-binding-evidence-smoke=PASS checks=" + checks);
    }

    private static void check(String languageId) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(languageId));
        Object token = new Object();
        var program = new ProgramDB("static-binding", language, language.getDefaultCompilerSpec(), token);
        var foreign = new ProgramDB("foreign", language, language.getDefaultCompilerSpec(), token);
        var directory = Files.createTempDirectory("forge-static-binding-");
        var saved = directory.resolve("program.db");
        long symbolId;
        long ownerId;
        try {
            int tx = program.startTransaction("saved static ownership");
            int foreignTx = foreign.startTransaction("foreign identities");
            try {
                long base = languageId.startsWith("MIPS") ? 0x80401000L : 0x401000;
                var entry = language.getDefaultSpace().getAddress(base);
                program.getMemory().createInitializedBlock("image", entry.subtract(16), 512, (byte) 0, TaskMonitor.DUMMY, false);
                foreign.getMemory().createInitializedBlock("image", entry, 512, (byte) 0, TaskMonitor.DUMMY, false);
                var body = new AddressSet(entry, entry.add(31));
                body.add(entry.add(40), entry.add(63));
                Function owner = program.getFunctionManager().createFunction("owner", entry, body, SourceType.USER_DEFINED);
                var other = program.getFunctionManager().createFunction("other", entry.add(80),
                    new AddressSet(entry.add(80), entry.add(95)), SourceType.USER_DEFINED);
                var foreignOwner = foreign.getFunctionManager().createFunction("owner", entry,
                    new AddressSet(entry, entry.add(63)), SourceType.USER_DEFINED);
                var importedNamespace = program.getSymbolTable().createNameSpace(program.getGlobalNamespace(),
                    "owner", SourceType.IMPORTED);
                var dataAddress = entry.add(256);
                program.getListing().createData(dataAddress, IntegerDataType.dataType);
                var symbol = program.getSymbolTable().createLabel(dataAddress, "hidden", importedNamespace, SourceType.IMPORTED);
                symbol.setPrimary();
                var foreignSymbol = foreign.getSymbolTable().createLabel(entry.add(256), "hidden", SourceType.USER_DEFINED);
                symbolId = symbol.getID();
                ownerId = owner.getSymbol().getID();
                String key = "static-" + symbolId;
                require(importedNamespace.getID() != ownerId, "same spelling is a distinct namespace");
                var diagnostics = new ArrayList<String>();
                require(GhidraStaticBindings.read(program, symbolId, TaskMonitor.DUMMY, diagnostics::add).status() == Status.ABSENT &&
                    diagnostics.isEmpty(), "namespace spelling does not create binding");
                require(!program.getOptionsNames().contains(GROUP), "read-only absence creates no group");
                reject(() -> GhidraStaticBindings.save(program, foreignSymbol, owner, "", "hidden", "foreign", TaskMonitor.DUMMY));
                reject(() -> GhidraStaticBindings.save(program, symbol, foreignOwner, "", "hidden", "foreign", TaskMonitor.DUMMY));
                reject(() -> GhidraStaticBindings.save(program, symbol, owner, "", "", "no display", TaskMonitor.DUMMY));
                reject(() -> GhidraStaticBindings.save(program, symbol, owner, "", "hidden", " ", TaskMonitor.DUMMY));
                reject(() -> GhidraStaticBindings.save(program, symbol, owner, "inner", "hidden", "missing block", TaskMonitor.DUMMY));
                require(!program.getOptionsNames().contains(GROUP), "rejected saves create no group");
                for (int at = 1; at <= 5; at++) {
                    int limit = at;
                    cancelled(() -> GhidraStaticBindings.save(program, symbol, owner, "", "hidden", "cancel", cancelAt(limit)));
                    require(!program.getOptionsNames().contains(GROUP), "cancelled save creates no group");
                }
                var range = new AddressSet(entry.add(8), entry.add(15));
                range.add(entry.add(40), entry.add(47));
                var blocks = List.of(new GhidraLexicalScopes.Block("inner", "", range));
                GhidraLexicalScopes.save(owner, "recorded tree", blocks, List.of(), TaskMonitor.DUMMY);
                GhidraStaticBindings.save(program, symbol, owner, "inner", "shadow", "explicit static ownership", TaskMonitor.DUMMY);
                var options = program.getOptions(GROUP);
                String original = options.getString(key, null);
                observe(program, symbolId, ownerId, "inner");
                GhidraStaticBindings.save(program, symbol, owner, "inner", "shadow", "explicit static ownership", TaskMonitor.DUMMY);
                require(original.equals(options.getString(key, null)), "deterministic record");
                symbol.setName("changed", SourceType.USER_DEFINED);
                rejected(program, symbolId, "renamed symbol");
                symbol.setName("hidden", SourceType.IMPORTED);
                symbol.setNamespace(other);
                rejected(program, symbolId, "conflicting actual function owner");
                reject(() -> GhidraStaticBindings.save(program, symbol, owner, "inner", "shadow", "contradiction", TaskMonitor.DUMMY));
                symbol.setNamespace(importedNamespace);
                program.getListing().clearCodeUnits(dataAddress, dataAddress.add(3), false);
                rejected(program, symbolId, "removed typed storage");
                program.getListing().createData(dataAddress, UnsignedIntegerDataType.dataType);
                rejected(program, symbolId, "same-width type replacement");
                program.getListing().clearCodeUnits(dataAddress, dataAddress.add(3), false);
                program.getListing().createData(dataAddress, IntegerDataType.dataType);
                observe(program, symbolId, ownerId, "inner");
                var properties = program.getUsrPropertyManager().getStringPropertyMap(GhidraLexicalScopes.PROPERTY_NAME);
                String lexical = properties.getString(entry);
                GhidraLexicalScopes.save(owner, "different assertion", blocks, List.of(), TaskMonitor.DUMMY);
                rejected(program, symbolId, "lexical evidence update");
                properties.add(entry, lexical);
                var smaller = new AddressSet(entry, entry.add(31));
                owner.setBody(smaller);
                rejected(program, symbolId, "scope outside changed body");
                owner.setBody(body);
                observe(program, symbolId, ownerId, "inner");
                byte[] bytes = Base64.getDecoder().decode(original.substring(7));
                byte[] trailing = Arrays.copyOf(bytes, bytes.length + 1);
                byte[] wrongVersion = bytes.clone();
                wrongVersion[3] = 2;
                var malformed = List.of("bad", "GDFSB1:%%%%", "GDFSB1:AA==",
                    "GDFSB1:" + Base64.getEncoder().encodeToString(trailing),
                    "GDFSB1:" + Base64.getEncoder().encodeToString(wrongVersion), "GDFSB1:" + "A".repeat(100000));
                for (String corrupt : malformed) {
                    options.setString(key, corrupt);
                    rejected(program, symbolId, "corrupt record");
                    require(corrupt.equals(options.getString(key, null)), "read never repairs rejected record");
                }
                options.setString(key, original);
                var secondAddress = entry.add(264);
                program.getListing().createData(secondAddress, IntegerDataType.dataType);
                var second = program.getSymbolTable().createLabel(secondAddress, "hidden", other, SourceType.USER_DEFINED);
                second.setPrimary();
                String secondKey = "static-" + second.getID();
                options.setString(secondKey, original);
                rejected(program, second.getID(), "record moved to different symbol");
                GhidraStaticBindings.remove(program, second.getID(), TaskMonitor.DUMMY);
                GhidraStaticBindings.save(program, second, other, "", "hidden", "actual function-owned static", TaskMonitor.DUMMY);
                require(GhidraStaticBindings.read(program, second.getID(), TaskMonitor.DUMMY, diagnostics::add).status() == Status.VALID,
                    "actual function ownership agrees with explicit binding");
                long retiredSymbol = second.getID();
                second.delete();
                var replacement = program.getSymbolTable().createLabel(secondAddress, "hidden", other, SourceType.USER_DEFINED);
                replacement.setPrimary();
                require(replacement.getID() != retiredSymbol, "replacement has a new symbol identity");
                rejected(program, retiredSymbol, "deleted symbol is not replaced by same name and address");
                GhidraStaticBindings.save(program, replacement, other, "", "hidden", "explicit new identity", TaskMonitor.DUMMY);
                var otherEntry = other.getEntryPoint();
                program.getFunctionManager().removeFunction(otherEntry);
                program.getFunctionManager().createFunction("other", otherEntry,
                    new AddressSet(otherEntry, otherEntry.add(15)), SourceType.USER_DEFINED);
                rejected(program, replacement.getID(), "deleted owner is not replaced by same name and entry");
                for (int at = 1; at <= 5; at++) {
                    int limit = at;
                    cancelled(() -> GhidraStaticBindings.read(program, symbolId, cancelAt(limit), diagnostics::add));
                    cancelled(() -> GhidraStaticBindings.save(program, symbol, owner, "inner", "shadow", "cancel", cancelAt(limit)));
                    require(original.equals(options.getString(key, null)), "cancellation preserves old binding");
                }
                GhidraStaticBindings.save(program, symbol, owner, "", "shadow", "explicit root ownership", TaskMonitor.DUMMY);
                require(GhidraStaticBindings.read(program, symbolId, TaskMonitor.DUMMY, diagnostics::add).binding().block().isEmpty(),
                    "explicit function root supported without inferred block");
                options.setString(key, original);
                owner.getSymbol().setName("renamed_owner", SourceType.USER_DEFINED);
                observe(program, symbolId, ownerId, "inner");
                cancelled(() -> GhidraStaticBindings.remove(program, symbolId, cancelAt(1)));
                require(options.getString(key, null).equals(original), "cancelled remove preserves binding");
                GhidraStaticBindings.remove(program, symbolId, TaskMonitor.DUMMY);
                require(GhidraStaticBindings.read(program, symbolId, TaskMonitor.DUMMY, diagnostics::add).status() == Status.ABSENT,
                    "explicit removal restores absence");
                options.setString(key, original);
                program.setImageBase(program.getImageBase().add(0x200000), true);
                require(original.equals(options.getString(key, null)), "rebase leaves identity record unchanged");
                observe(program, symbolId, ownerId, "inner");
                options.removeOption(key);
                options.setInt(key, 17);
                rejected(program, symbolId, "wrong option type");
                reject(() -> GhidraStaticBindings.save(program, symbol, owner, "", "shadow", "wrong option type", TaskMonitor.DUMMY));
                require(options.getInt(key, 0) == 17, "foreign option value preserved");
                options.removeOption(key);
                options.setString(key, original);
            }
            finally {
                program.endTransaction(tx, true);
                foreign.endTransaction(foreignTx, true);
            }
            program.getDBHandle().saveAs(saved.toFile(), false, TaskMonitor.DUMMY);
            byte[] before = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(saved));
            var modified = Files.getLastModifiedTime(saved);
            var handle = new DBHandle(saved.toFile());
            Object reopenedToken = new Object();
            ProgramDB reopened = null;
            try {
                reopened = new ProgramDB(handle, OpenMode.IMMUTABLE, TaskMonitor.DUMMY, reopenedToken);
                observe(reopened, symbolId, ownerId, "inner");
            }
            finally {
                if (reopened != null) reopened.release(reopenedToken);
                else handle.close();
            }
            require(Arrays.equals(before, MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(saved))) &&
                modified.equals(Files.getLastModifiedTime(saved)), "immutable database unchanged");
            System.out.println("static-binding-target=PASS " + languageId);
        }
        finally {
            program.release(token);
            foreign.release(token);
            Files.deleteIfExists(saved);
            Files.deleteIfExists(directory);
        }
    }

    private static void observe(ProgramDB program, long symbolId, long ownerId, String block) throws Exception {
        var diagnostics = new ArrayList<String>();
        var result = GhidraStaticBindings.read(program, symbolId, TaskMonitor.DUMMY, diagnostics::add);
        require(result.status() == Status.VALID && diagnostics.isEmpty(), "valid association " + diagnostics);
        var binding = result.binding();
        require(binding.symbol().getID() == symbolId && binding.owner().getSymbol().getID() == ownerId &&
            binding.block().equals(block) && binding.displayName().equals("shadow"), "exact identity and explicit display");
        require(binding.data().getLength() == 4 && binding.data().getAddress().subtract(binding.owner().getEntryPoint()) == 256,
            "current typed storage survives rebase");
        require(binding.symbol().getParentNamespace().getID() != ownerId, "binding does not rewrite the imported namespace");
    }

    private static void rejected(ProgramDB program, long symbolId, String label) throws Exception {
        var diagnostics = new ArrayList<String>();
        var result = GhidraStaticBindings.read(program, symbolId, TaskMonitor.DUMMY, diagnostics::add);
        require(result.status() == Status.REJECTED && result.binding() == null && diagnostics.size() == 1,
            label + ": must distinguish rejected evidence from absence " + diagnostics);
    }

    private static TaskMonitor cancelAt(int at) {
        return new TaskMonitorAdapter(true) {
            private int visits;
            @Override public void checkCancelled() throws CancelledException {
                if (++visits == at) throw new CancelledException();
            }
        };
    }

    @FunctionalInterface private interface Action { void run() throws Exception; }

    private static void reject(Action action) throws Exception {
        try { action.run(); throw new AssertionError("invalid static binding accepted"); }
        catch (IllegalArgumentException expected) { checks++; }
    }

    private static void cancelled(Action action) throws Exception {
        try { action.run(); throw new AssertionError("cancellation ignored"); }
        catch (CancelledException expected) { checks++; }
    }

    private static void require(boolean value, String message) {
        checks++;
        if (!value) throw new AssertionError(message);
    }
}
