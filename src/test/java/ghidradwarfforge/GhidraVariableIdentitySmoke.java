package ghidradwarfforge;

import com.google.gson.GsonBuilder;
import db.DBHandle;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.data.OpenMode;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;

/** Negative identity controls: record keys survive edits but are reusable after undo/fork. */
public final class GhidraVariableIdentitySmoke {
    private static int checks;
    private record Identity(String database, String symbol, String name, String storage, String type) { }

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        Path root = Path.of(args[1]);
        Files.createDirectories(root);
        Path work = Files.createTempDirectory(root, "run.");
        var results = new ArrayList<Object>();
        for (String language : List.of("x86:LE:64:default", "AARCH64:LE:64:v8A", "MIPS:BE:32:default", "MIPS:LE:32:default")) {
            results.add(fixture(language, work.resolve(language.replace(':', '_'))));
        }
        var result = new LinkedHashMap<String, Object>();
        result.put("status", "PASS");
        result.put("profiles", results);
        result.put("checks", checks);
        result.put("conclusion", "Database/symbol IDs are observations, not proof of uninterrupted declaration identity across undo or copied databases.");
        Files.writeString(work.resolve("result.json"), new GsonBuilder().setPrettyPrinting().create().toJson(result) + "\n");
        System.out.println("ghidra-variable-identity=PASS profiles=4 checks=" + checks + " results=" + work);
    }

    private static Object fixture(String languageId, Path directory) throws Exception {
        Files.createDirectory(directory);
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(languageId));
        Object owner = new Object();
        var program = new ProgramDB("identity fixture", language, language.getDefaultCompilerSpec(), owner);
        try {
            var entry = language.getDefaultSpace().getAddress(0x1000);
            transact(program, "initial declaration", () -> {
                program.getMemory().createInitializedBlock("code", entry, 32, (byte) 0, TaskMonitor.DUMMY, false);
                var function = program.getFunctionManager().createFunction("owner", entry,
                    new AddressSet(entry, entry.add(31)), SourceType.USER_DEFINED);
                function.addLocalVariable(new LocalVariableImpl("original", IntegerDataType.dataType, -16, program), SourceType.USER_DEFINED);
            });
            Identity initial = identity(program, program.getFunctionManager().getFunctionAt(entry).getLocalVariables()[0]);
            transact(program, "rename and type edit", () -> {
                var function = program.getFunctionManager().getFunctionAt(entry);
                function.setName("renamed_owner", SourceType.USER_DEFINED);
                var variable = function.getLocalVariables()[0];
                variable.setName("renamed_local", SourceType.USER_DEFINED);
                variable.setDataType(FloatDataType.dataType, SourceType.USER_DEFINED);
            });
            Identity renamed = identity(program, program.getFunctionManager().getFunctionAt(entry).getLocalVariables()[0]);
            require(sameRecord(initial, renamed) && !initial.name().equals(renamed.name()) && !initial.type().equals(renamed.type()),
                "rename/type edit did not preserve record key");
            long delta = 0x10000;
            transact(program, "rebase", () -> program.setImageBase(program.getImageBase().add(delta), true));
            var rebasedEntry = entry.add(delta);
            Identity rebased = identity(program, program.getFunctionManager().getFunctionAt(rebasedEntry).getLocalVariables()[0]);
            require(rebased.equals(renamed), "rebase changed database/local record identity");
            transact(program, "replace declaration", () -> {
                var function = program.getFunctionManager().getFunctionAt(rebasedEntry);
                function.removeVariable(function.getLocalVariables()[0]);
                function.addLocalVariable(new LocalVariableImpl("replacement", IntegerDataType.dataType, -16, program), SourceType.USER_DEFINED);
            });
            Identity replacement = identity(program, program.getFunctionManager().getFunctionAt(rebasedEntry).getLocalVariables()[0]);
            require(!replacement.symbol().equals(rebased.symbol()), "ordinary deletion reused record key");
            require(program.canUndo(), "missing replacement transaction in undo history");
            program.undo();
            Identity restored = identity(program, program.getFunctionManager().getFunctionAt(rebasedEntry).getLocalVariables()[0]);
            require(restored.equals(rebased), "undo did not restore old declaration");
            transact(program, "new branch declaration", () -> {
                var function = program.getFunctionManager().getFunctionAt(rebasedEntry);
                function.addLocalVariable(new LocalVariableImpl("different_declaration", IntegerDataType.dataType, -24, program), SourceType.USER_DEFINED);
            });
            Variable reused = java.util.Arrays.stream(program.getFunctionManager().getFunctionAt(rebasedEntry).getLocalVariables())
                .filter(variable -> variable.getName().equals("different_declaration")).findFirst().orElseThrow();
            Identity forked = identity(program, reused);
            require(sameRecord(replacement, forked) && !replacement.name().equals(forked.name()) && !replacement.storage().equals(forked.storage()),
                "expected undo/branch record reuse was not reproduced");
            Path saved = directory.resolve("saved.db");
            program.getDBHandle().saveAs(saved.toFile(), false, TaskMonitor.DUMMY);
            String savedHash = sha(saved);
            Identity reopened = reopen(saved, rebasedEntry.getOffset(), "different_declaration");
            require(reopened.equals(forked), "first save/reopen changed record observation");
            Path copied = Files.copy(saved, directory.resolve("copied.db"));
            Identity copy = reopen(copied, rebasedEntry.getOffset(), "different_declaration");
            require(copy.equals(reopened), "byte-copy identity differs before divergent edits");
            require(sha(saved).equals(savedHash) && sha(copied).equals(savedHash), "read-only reopen changed database bytes");
            Object otherOwner = new Object();
            var other = new ProgramDB("independent", language, language.getDefaultCompilerSpec(), otherOwner);
            try { require(program.getUniqueProgramID() != other.getUniqueProgramID(), "independent programs share database ID"); }
            finally { other.release(otherOwner); }
            var observations = new LinkedHashMap<String, Object>();
            observations.put("language", languageId);
            observations.put("initial", initial);
            observations.put("renamedAndRetyped", renamed);
            observations.put("rebased", rebased);
            observations.put("replacementBeforeUndo", replacement);
            observations.put("differentDeclarationAfterUndo", forked);
            observations.put("reopened", reopened);
            observations.put("copied", copy);
            observations.put("savedDatabaseSha256", savedHash);
            return observations;
        }
        finally { program.release(owner); }
    }

    private static Identity reopen(Path file, long entry, String name) throws Exception {
        Object owner = new Object();
        var handle = new DBHandle(file.toFile());
        ProgramDB program = null;
        try {
            program = new ProgramDB(handle, OpenMode.IMMUTABLE, TaskMonitor.DUMMY, owner);
            var function = program.getFunctionManager().getFunctionAt(program.getAddressFactory().getDefaultAddressSpace().getAddress(entry));
            Variable found = java.util.Arrays.stream(function.getLocalVariables()).filter(v -> v.getName().equals(name)).findFirst().orElseThrow();
            return identity(program, found);
        }
        finally {
            if (program == null) handle.close();
            else program.release(owner);
        }
    }

    private static Identity identity(ProgramDB program, Variable variable) {
        require(variable.getSymbol() != null && variable.getFunction() != null, "variable lacks database symbol/owner");
        return new Identity(Long.toUnsignedString(program.getUniqueProgramID()), Long.toUnsignedString(variable.getSymbol().getID()),
            variable.getName(), variable.getVariableStorage().toString(), variable.getDataType().getName());
    }
    private static boolean sameRecord(Identity first, Identity second) {
        return first.database().equals(second.database()) && first.symbol().equals(second.symbol());
    }
    private static String sha(Path file) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(file)));
    }
    private interface Action { void run() throws Exception; }
    private static void transact(ProgramDB program, String description, Action action) throws Exception {
        int transaction = program.startTransaction(description);
        boolean commit = false;
        try { action.run(); commit = true; }
        finally { program.endTransaction(transaction, commit); }
    }
    private static void require(boolean value, String message) { checks++; if (!value) throw new AssertionError(message); }
}
