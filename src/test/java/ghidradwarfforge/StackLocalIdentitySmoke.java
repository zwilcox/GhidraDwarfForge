package ghidradwarfforge;

import java.io.File;
import java.nio.file.Files;
import java.security.MessageDigest;
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
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariable;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;

/** Saved listing identities are distinct even when their stack bytes overlap. */
public final class StackLocalIdentitySmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (String language : List.of("x86:LE:64:default", "AARCH64:LE:64:v8A",
                "ARM:LE:32:v8", "MIPS:BE:32:default", "MIPS:LE:32:default")) {
            check(language);
        }
        System.out.println("stack-local-identity-smoke=PASS checks=" + checks);
    }

    private static void check(String languageId) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(languageId));
        Object owner = new Object();
        var program = new ProgramDB("stack-local-identity", language, language.getDefaultCompilerSpec(), owner);
        var directory = Files.createTempDirectory("forge-stack-local-identity-");
        var saved = directory.resolve("program.db");
        try {
            long[] ids;
            int tx = program.startTransaction("distinct saved stack identities");
            try {
                var entry = language.getDefaultSpace().getAddress(0x1000);
                program.getMemory().createInitializedBlock("body", entry, 64, (byte) 0, TaskMonitor.DUMMY, false);
                Function function = program.getFunctionManager().createFunction("reuse", entry,
                    new AddressSet(entry, entry.add(63)), SourceType.USER_DEFINED);
                int[] offsets = { -16, -16, -14 };
                int[] starts = { 4, 20, 36 };
                ids = new long[3];
                for (int i = 0; i < offsets.length; i++) {
                    // Constructors reject nonzero stack starts. The public setter on
                    // the attached database object retains the analyst's exact field.
                    var local = (LocalVariable) function.addLocalVariable(new LocalVariableImpl(
                        "slot" + i, IntegerDataType.dataType, offsets[i], program, SourceType.USER_DEFINED),
                        SourceType.USER_DEFINED);
                    require(local.setFirstUseOffset(starts[i]), "attached setter rejected offset");
                    ids[i] = local.getSymbol().getID();
                    require(function.getLocalVariables().length == i + 1, "overlap replaced another identity");
                }
                inspect(function, ids);
            }
            finally { program.endTransaction(tx, true); }
            program.getDBHandle().saveAs(saved.toFile(), false, TaskMonitor.DUMMY);
            byte[] before = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(saved));
            Object reopenedOwner = new Object();
            DBHandle handle = new DBHandle(saved.toFile());
            ProgramDB reopened = null;
            try {
                reopened = new ProgramDB(handle, OpenMode.IMMUTABLE, TaskMonitor.DUMMY, reopenedOwner);
                inspect(reopened.getFunctionManager().getFunctionAt(
                    reopened.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000)), ids);
            }
            finally {
                if (reopened != null) reopened.release(reopenedOwner);
                else handle.close();
            }
            require(Arrays.equals(before, MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(saved))),
                "read-only inspection modified saved database");
            System.out.println("stack-local-identities=" + languageId + " PASS");
        }
        finally {
            program.release(owner);
            Files.deleteIfExists(saved);
            Files.deleteIfExists(directory);
        }
    }

    private static void inspect(Function function, long[] ids) {
        require(function != null && function.getLocalVariables().length == 3, "three identities must survive");
        var locals = function.getLocalVariables();
        int[] offsets = { -16, -16, -14 };
        int[] starts = { 4, 20, 36 };
        for (int i = 0; i < ids.length; i++) {
            String name = "slot" + i;
            var local = Arrays.stream(locals).filter(value -> value.getName().equals(name)).findFirst().orElseThrow();
            require(local.getSymbol().getID() == ids[i] && local.getFirstUseOffset() == starts[i] &&
                local.getStackOffset() == offsets[i] && local.getLength() == 4 &&
                local.getSource() == SourceType.USER_DEFINED && local.getFunction() == function,
                "saved identity, source, storage or start changed for " + name);
            for (var other : locals) {
                require(local.getVariableStorage().intersects(other.getVariableStorage()),
                    "negative lifetime fixture must actually overlap");
            }
        }
        require(Arrays.stream(ids).distinct().count() == 3, "distinct symbol IDs required");
    }

    private static void require(boolean value, String message) {
        checks++;
        if (!value) throw new AssertionError(message);
    }
}
