package ghidradwarfforge;

import java.io.File;
import java.nio.ByteBuffer;
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
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.GhidraClassBindings.Status;

/** Actual saved identities, preference changes, cancellation and immutable reopen. */
public final class ClassBindingEvidenceSmoke {
    private static int checks;
    private static final String GROUP = GhidraClassBindings.OPTIONS_NAME;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (String language : List.of("x86:LE:64:default", "AARCH64:LE:64:v8A",
                "ARM:LE:32:v8", "MIPS:BE:32:default", "MIPS:LE:32:default")) check(language);
        System.out.println("class-binding-evidence=PASS checks=" + checks);
    }

    private static Structure addType(ProgramDB program, String category) {
        var type = new StructureDataType(new CategoryPath(category), "Layout", 0);
        type.add(IntegerDataType.dataType, "value", "explicit fixture member");
        return (Structure) program.getDataTypeManager().addDataType(type, DataTypeConflictHandler.DEFAULT_HANDLER);
    }

    private static void check(String languageId) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(languageId));
        Object token = new Object();
        var program = new ProgramDB("class-binding", language, language.getDefaultCompilerSpec(), token);
        var foreign = new ProgramDB("foreign", language, language.getDefaultCompilerSpec(), token);
        var directory = Files.createTempDirectory("forge-class-binding-");
        var saved = directory.resolve("program.db");
        long classId;
        long typeId;
        String original;
        try {
            int tx = program.startTransaction("explicit binding controls");
            int otherTx = foreign.startTransaction("foreign identity controls");
            try {
                var owner = program.getSymbolTable().createClass(program.getGlobalNamespace(), "Counter", SourceType.USER_DEFINED);
                var otherOwner = foreign.getSymbolTable().createClass(foreign.getGlobalNamespace(), "Counter", SourceType.USER_DEFINED);
                classId = owner.getID();
                String key = "class-" + classId;
                var type = addType(program, "/one");
                var decoy = addType(program, "/two");
                var foreignType = addType(foreign, "/one");
                typeId = program.getDataTypeManager().getID(type);
                require(owner.getID() == otherOwner.getID() &&
                    typeId == foreign.getDataTypeManager().getID(foreignType),
                    "foreign-program controls must collide numerically");
                var diagnostics = new ArrayList<String>();
                require(GhidraClassBindings.read(program, classId, TaskMonitor.DUMMY, diagnostics::add).status() == Status.ABSENT,
                    "absence does not invent evidence");
                GhidraClassBindings.remove(program, classId, TaskMonitor.DUMMY);
                require(!program.getOptionsNames().contains(GROUP) && diagnostics.isEmpty(), "absent read/remove must not create group");
                reject(() -> GhidraClassBindings.save(program, otherOwner, type, "foreign owner", TaskMonitor.DUMMY));
                reject(() -> GhidraClassBindings.save(program, owner, foreignType, "foreign type", TaskMonitor.DUMMY));
                reject(() -> GhidraClassBindings.save(program, owner, new StructureDataType("unsaved", 0), "unsaved", TaskMonitor.DUMMY));
                reject(() -> GhidraClassBindings.save(program, owner, type, " ", TaskMonitor.DUMMY));
                reject(() -> GhidraClassBindings.save(program, owner, type, "x".repeat(8193), TaskMonitor.DUMMY));
                require(!program.getOptionsNames().contains(GROUP), "rejected saves must not create group");
                for (int limit = 1; limit <= 3; limit++) {
                    var monitor = cancelAt(limit);
                    cancelled(() -> GhidraClassBindings.save(program, owner, type, "cancel", monitor));
                    require(!program.getOptionsNames().contains(GROUP), "cancelled initial save creates no group");
                }
                GhidraClassBindings.save(program, owner, type, "analyst selected canonical layout", TaskMonitor.DUMMY);
                var options = program.getOptions(GROUP);
                original = options.getString(key, null);
                observe(program, classId, typeId, "Layout", 4);
                GhidraClassBindings.save(program, owner, type, "analyst selected canonical layout", TaskMonitor.DUMMY);
                require(original.equals(options.getString(key, null)), "deterministic record");
                String maximumEvidence = "測".repeat(8192);
                GhidraClassBindings.save(program, owner, type, maximumEvidence, TaskMonitor.DUMMY);
                var maximum = GhidraClassBindings.read(program, classId, TaskMonitor.DUMMY, diagnostics::add);
                require(maximum.status() == Status.VALID && maximum.binding().evidence().equals(maximumEvidence),
                    "maximum multibyte evidence round trip");
                GhidraClassBindings.save(program, owner, type, "analyst selected canonical layout", TaskMonitor.DUMMY);
                require(original.equals(options.getString(key, null)), "explicit update restores identical binding");
                require(program.getDataTypeManager().getID(decoy) != typeId, "same-name category types remain distinct");
                program.setPreferredRootNamespaceCategoryPath("/two");
                observe(program, classId, typeId, "Layout", 4);
                owner.getSymbol().setName("RenamedClass", SourceType.USER_DEFINED);
                var namespace = program.getSymbolTable().createNameSpace(program.getGlobalNamespace(), "moved", SourceType.USER_DEFINED);
                owner.getSymbol().setNamespace(namespace);
                type.setName("RenamedLayout");
                type.setCategoryPath(new CategoryPath("/moved-layout"));
                type.add(IntegerDataType.dataType, "additional", "later analyst edit");
                observe(program, classId, typeId, "RenamedLayout", 8);
                require(original.equals(options.getString(key, null)), "identity binding survives rename/category/layout edits without rewrite");
                var entry = language.getDefaultSpace().getAddress(0x401000);
                program.getMemory().createInitializedBlock("body", entry, 16, (byte) 0, TaskMonitor.DUMMY, false);
                program.setImageBase(program.getImageBase().add(0x200000), true);
                observe(program, classId, typeId, "RenamedLayout", 8);
                require(original.equals(options.getString(key, null)), "rebase does not rewrite identity");
                for (int limit = 1; limit <= 4; limit++) {
                    var monitor = cancelAt(limit);
                    cancelled(() -> GhidraClassBindings.read(program, owner.getID(), monitor, diagnostics::add));
                    require(original.equals(options.getString(key, null)), "cancelled read retains evidence");
                }
                for (int limit = 1; limit <= 3; limit++) {
                    var monitor = cancelAt(limit);
                    cancelled(() -> GhidraClassBindings.save(program, owner, decoy, "replacement", monitor));
                    require(original.equals(options.getString(key, null)), "cancelled replacement retains evidence");
                }
                cancelled(() -> GhidraClassBindings.remove(program, owner.getID(), cancelAt(1)));
                require(original.equals(options.getString(key, null)), "cancelled removal retains binding");
                byte[] bytes = Base64.getDecoder().decode(original.substring("GDFCB1:".length()));
                var malformed = new ArrayList<String>(List.of("", "GDFCB2:AAAA", "GDFCB1:!", "GDFCB1:" + "A".repeat(50000),
                    "GDFCB1:" + Base64.getEncoder().encodeToString(Arrays.copyOf(bytes, 10)),
                    "GDFCB1:" + Base64.getEncoder().encodeToString(Arrays.copyOf(bytes, bytes.length + 1))));
                for (int offset : List.of(4, 12, 20)) {
                    byte[] changed = bytes.clone();
                    ByteBuffer.wrap(changed).putLong(offset, Long.MAX_VALUE);
                    malformed.add("GDFCB1:" + Base64.getEncoder().encodeToString(changed));
                }
                byte[] changed = bytes.clone();
                ByteBuffer.wrap(changed).putInt(0, 2);
                malformed.add("GDFCB1:" + Base64.getEncoder().encodeToString(changed));
                for (String invalid : malformed) {
                    options.setString(key, invalid);
                    rejected(program, classId);
                    require(invalid.equals(options.getString(key, null)), "rejected evidence is not repaired or replaced");
                }
                GhidraClassBindings.save(program, owner, type, "analyst selected canonical layout", TaskMonitor.DUMMY);
                require(original.equals(options.getString(key, null)), "explicit save can replace malformed evidence");
                options.removeOption(key);
                options.setInt(key, 27);
                rejected(program, classId);
                reject(() -> GhidraClassBindings.save(program, owner, type, "wrong option kind", TaskMonitor.DUMMY));
                require(options.getInt(key, 0) == 27, "foreign option kind preserved");
                options.removeOption(key);
                options.setString(key, original);
                var deletedOwner = program.getSymbolTable().createClass(program.getGlobalNamespace(), "Deleted", SourceType.USER_DEFINED);
                long deletedId = deletedOwner.getID();
                GhidraClassBindings.save(program, deletedOwner, decoy, "deleted owner", TaskMonitor.DUMMY);
                deletedOwner.getSymbol().delete();
                rejected(program, deletedId);
                var recreatedOwner = program.getSymbolTable().createClass(program.getGlobalNamespace(), "Deleted", SourceType.USER_DEFINED);
                require(recreatedOwner.getID() != deletedId, "recreated class must have distinct saved identity");
                rejected(program, deletedId);
                var deletedTypeOwner = program.getSymbolTable().createClass(program.getGlobalNamespace(), "DeletedType", SourceType.USER_DEFINED);
                GhidraClassBindings.save(program, deletedTypeOwner, decoy, "deleted type", TaskMonitor.DUMMY);
                program.getDataTypeManager().remove(decoy);
                addType(program, "/two");
                rejected(program, deletedTypeOwner.getID());
                GhidraClassBindings.remove(program, deletedTypeOwner.getID(), TaskMonitor.DUMMY);
                require(GhidraClassBindings.read(program, deletedTypeOwner.getID(), TaskMonitor.DUMMY, diagnostics::add).status() == Status.ABSENT,
                    "explicit removal distinguishes absence from rejection");
                observe(program, classId, typeId, "RenamedLayout", 8);
            }
            finally {
                program.endTransaction(tx, true);
                foreign.endTransaction(otherTx, true);
            }
            program.getDBHandle().saveAs(saved.toFile(), false, TaskMonitor.DUMMY);
            byte[] before = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(saved));
            var modified = Files.getLastModifiedTime(saved);
            var handle = new DBHandle(saved.toFile());
            var reopenedToken = new Object();
            ProgramDB reopened = null;
            try {
                reopened = new ProgramDB(handle, OpenMode.IMMUTABLE, TaskMonitor.DUMMY, reopenedToken);
                observe(reopened, classId, typeId, "RenamedLayout", 8);
                require(original.equals(reopened.getOptions(GROUP).getString("class-" + classId, null)), "serialized binding survives immutable reopen");
            }
            finally {
                if (reopened != null) reopened.release(reopenedToken);
                else handle.close();
            }
            require(Arrays.equals(before, MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(saved))) &&
                modified.equals(Files.getLastModifiedTime(saved)), "immutable database bytes and timestamp unchanged");
            System.out.println("class-binding-target=PASS " + languageId);
        }
        finally {
            program.release(token);
            foreign.release(token);
            Files.deleteIfExists(saved);
            Files.deleteIfExists(directory);
        }
    }

    private static void observe(ProgramDB program, long classId, long typeId, String name, int length) throws Exception {
        var diagnostics = new ArrayList<String>();
        var result = GhidraClassBindings.read(program, classId, TaskMonitor.DUMMY, diagnostics::add);
        require(result.status() == Status.VALID && diagnostics.isEmpty(),
            "valid explicit record: " + result.status() + " " + diagnostics + " groups=" + program.getOptionsNames());
        var binding = result.binding();
        require(binding.classId() == classId && binding.typeId() == typeId && binding.type().getName().equals(name) &&
            binding.type().getLength() == length && binding.evidence().equals("analyst selected canonical layout"), "current canonical identity/layout");
    }

    private static void rejected(ProgramDB program, long classId) throws Exception {
        var diagnostics = new ArrayList<String>();
        var result = GhidraClassBindings.read(program, classId, TaskMonitor.DUMMY, diagnostics::add);
        require(result.status() == Status.REJECTED && result.binding() == null && diagnostics.size() == 1 &&
            diagnostics.getFirst().startsWith("Omitted explicit class binding"), "invalid evidence must not look absent");
    }

    private static TaskMonitor cancelAt(int limit) {
        return new TaskMonitorAdapter(true) {
            private int visits;
            @Override public void checkCancelled() throws CancelledException {
                if (++visits == limit) throw new CancelledException();
            }
        };
    }

    private interface Operation { void run() throws Exception; }

    private static void reject(Operation operation) throws Exception {
        checks++;
        try { operation.run(); }
        catch (IllegalArgumentException expected) { return; }
        throw new AssertionError("invalid binding save accepted");
    }

    private static void cancelled(Operation operation) throws Exception {
        checks++;
        try { operation.run(); }
        catch (CancelledException expected) { return; }
        throw new AssertionError("binding operation ignored cancellation");
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
