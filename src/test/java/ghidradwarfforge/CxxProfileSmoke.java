package ghidradwarfforge;

import com.google.gson.*;
import java.io.File;
import java.io.IOException;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

import db.DBHandle;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.data.OpenMode;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;
import ghidradwarfforge.output.CxxSelection;
import ghidradwarfforge.targets.CxxAbiProfile;
import ghidradwarfforge.types.InheritanceModel;
import ghidradwarfforge.types.InheritanceModel.*;

/** Actual ProgramDB transactions, strict analyst input, retained evidence and read-only inventory. */
public final class CxxProfileSmoke {
    private static final TaskMonitor MONITOR = TaskMonitor.DUMMY;
    private static final Gson JSON = new Gson();
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        check("x86:LE:64:default", CxxAbiProfile.ITANIUM_X86_64);
        check("AARCH64:LE:64:v8A", CxxAbiProfile.ITANIUM_AARCH64);
        System.out.println("cxx-profile=PASS checks=" + checks);
    }

    private static void check(String languageId, CxxAbiProfile abi) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(languageId));
        Object consumer = new Object();
        var program = new ProgramDB("configuration", language, language.getDefaultCompilerSpec(), consumer);
        Path directory = Files.createTempDirectory("forge-cxx-profile-");
        Path selected = directory.resolve("selection.json"), saved = directory.resolve("program.db");
        try {
            long classId, typeId, localId, externalId;
            int tx = program.startTransaction("analyst fixture");
            try {
                var owner = program.getSymbolTable().createClass(program.getGlobalNamespace(), "Mixed", SourceType.USER_DEFINED);
                var layout = new StructureDataType("Mixed", 0);
                layout.add(IntegerDataType.dataType, "value", "fixture");
                var structure = program.getDataTypeManager().addDataType(layout, DataTypeConflictHandler.DEFAULT_HANDLER);
                classId = owner.getID(); typeId = program.getDataTypeManager().getID(structure);
                var address = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x401000);
                program.getMemory().createInitializedBlock("body", address, 4, (byte) 0x42, MONITOR, false);
                var local = program.getFunctionManager().createFunction("implemented", owner, address,
                    new AddressSet(address, address.add(3)), SourceType.USER_DEFINED);
                local.setCallingConvention("__thiscall"); local.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
                var library = program.getExternalManager().addExternalLibraryName("Declarations", SourceType.USER_DEFINED);
                var externalOwner = program.getSymbolTable().createClass(library, "Mixed", SourceType.USER_DEFINED);
                var external = program.getExternalManager().addExtFunction(externalOwner, "declared", null, SourceType.USER_DEFINED).getFunction();
                external.setCallingConvention("__thiscall"); external.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
                localId = local.getID(); externalId = external.getID();
                program.getOptions("Analyst").setString("keep", "independent saved information");
            }
            finally { program.endTransaction(tx, true); }
            var selection = new CxxSelection(program.getUniqueProgramID(), languageId,
                program.getCompilerSpec().getCompilerSpecID().toString(),
                List.of(new CxxSelection.ClassBinding(classId, typeId, "explicit canonical type")),
                List.of(new GhidraDeclarationBindings.Binding(externalId, classId, "explicit addressless ownership")),
                new InheritanceModel(abi, List.of(), List.of(
                    new VirtualMethod(localId, 0, Access.PUBLIC, Virtuality.VIRTUAL, "local slot"),
                    new VirtualMethod(externalId, 1, Access.PUBLIC, Virtuality.PURE_VIRTUAL, "pure slot"))),
                List.of(), new CxxSelection.Removals(List.of(), List.of(), List.of()));
            Map<String, String> before = records(program);
            String physical = physical(program);
            var inspected = GhidraCxxProfile.inspect(program, "Mixed", MONITOR);
            require(records(program).equals(before), "inspect has no metadata side effects");
            require(((List<?>) inspected.get("classes")).size() == 2, "inventory keeps distinct saved class identities: " + inspected);
            require(!GhidraCxxProfile.configure(program, selection, false, MONITOR).saved(), "preview reports unsaved");
            require(records(program).equals(before), "successful preview restores all records");
            require(physical(program).equals(physical), "preview preserves actual program state");
            var midCancel = new TaskMonitorAdapter(true) {
                @Override public void checkCancelled() throws CancelledException {
                    if (program.getOptionsNames().contains(GhidraClassBindings.OPTIONS_NAME) &&
                            program.getOptions(GhidraClassBindings.OPTIONS_NAME).contains("class-" + classId)) {
                        throw new CancelledException();
                    }
                }
            };
            try { GhidraCxxProfile.configure(program, selection, true, midCancel); throw new AssertionError("ignored cancellation after write"); }
            catch (CancelledException expected) { checks++; }
            require(records(program).equals(before), "cancellation after mutation restores records");
            var absentTable = new GhidraVtableBindings.Request(Long.MAX_VALUE, classId, "_ZTV5Mixed", "Mixed", 24,
                List.of(new GhidraVtableBindings.AddressPoint(16, 0, "primary")), "late missing symbol control");
            rejects(() -> GhidraCxxProfile.configure(program, copy(selection, List.of(absentTable), selection.remove()), true, MONITOR));
            require(records(program).equals(before), "late vtable failure rolls back classes declarations and inheritance");
            require(GhidraCxxProfile.configure(program, selection, true, MONITOR).saved(), "apply commits");
            Map<String, String> committed = records(program);
            require(!committed.equals(before), "apply actually persisted metadata");
            require(GhidraInheritanceBindings.read(program, MONITOR, ignored -> { }).model().equals(selection.inheritance()), "selected mixed methods retained");
            require(physical(program).equals(physical), "apply changes only configuration metadata");
            GhidraCxxProfile.configure(program, selection, true, MONITOR);
            require(records(program).equals(committed), "repeat application deterministic");
            var changedEvidence = new CxxSelection(selection.programId(), selection.language(), selection.compiler(),
                List.of(new CxxSelection.ClassBinding(classId, typeId, "revised evidence")), selection.declarations(),
                selection.inheritance(), List.of(), selection.remove());
            GhidraCxxProfile.configure(program, changedEvidence, false, MONITOR);
            require(records(program).equals(committed), "preview restores previously committed evidence bytes");
            rejects(() -> GhidraCxxProfile.configure(program, copy(changedEvidence, List.of(absentTable), selection.remove()), true, MONITOR));
            require(records(program).equals(committed), "late failure restores overwritten evidence bytes");
            var retained = new CxxSelection(selection.programId(), selection.language(), selection.compiler(), List.of(), List.of(),
                selection.inheritance(), List.of(), selection.remove());
            GhidraCxxProfile.configure(program, retained, true, MONITOR);
            require(records(program).equals(committed), "unselected valid bindings retained");
            var cleared = new CxxSelection(selection.programId(), selection.language(), selection.compiler(), List.of(), List.of(),
                new InheritanceModel(abi, List.of(), List.of()), List.of(), selection.remove());
            GhidraCxxProfile.configure(program, cleared, true, MONITOR);
            require(GhidraInheritanceBindings.read(program, MONITOR, ignored -> { }).model().virtualMethods().isEmpty(),
                "empty selected relationship graph explicitly replaces prior methods");
            GhidraCxxProfile.configure(program, selection, true, MONITOR);
            require(records(program).equals(committed), "relationship restoration deterministic");
            String text = JSON.toJson(GhidraCxxProfile.inspect(program, "not-a-match", MONITOR).get("selection"));
            Files.writeString(selected, text);
            require(CxxSelection.read(selected, () -> false).equals(selection), "inventory selection roundtrip independent of candidate filter");
            parserControls(selected, text);
            for (String key : List.of("program_id", "language", "compiler")) {
                var other = JsonParser.parseString(text).getAsJsonObject();
                other.addProperty(key, key.equals("program_id") ? Long.toString(selection.programId() ^ 1) : "wrong");
                Files.writeString(selected, other.toString());
                var mismatched = CxxSelection.read(selected, () -> false);
                rejects(() -> GhidraCxxProfile.configure(program, mismatched, true, MONITOR));
                require(records(program).equals(committed), "wrong target preserves metadata");
            }
            tx = program.startTransaction("stale retained control");
            try { program.getOptions(GhidraClassBindings.OPTIONS_NAME).setString("class-999999", "invalid old record"); }
            finally { program.endTransaction(tx, true); }
            Map<String, String> stale = records(program);
            rejects(() -> GhidraCxxProfile.configure(program, selection, true, MONITOR));
            require(records(program).equals(stale), "stale retained evidence never silently removed");
            var removals = new CxxSelection.Removals(List.of(999999L), List.of(), List.of());
            GhidraCxxProfile.configure(program, copy(selection, List.of(), removals), true, MONITOR);
            require(records(program).equals(committed), "explicit removal recovers configuration");
            require(physical(program).equals(physical), "all negative cases preserve independent state");
            program.getDBHandle().saveAs(saved.toFile(), false, MONITOR);
            byte[] hash = digest(saved); var stamp = Files.getLastModifiedTime(saved);
            var handle = new DBHandle(saved.toFile()); Object reopenedConsumer = new Object(); ProgramDB reopened = null;
            try {
                reopened = new ProgramDB(handle, OpenMode.IMMUTABLE, MONITOR, reopenedConsumer);
                require(JSON.toJson(GhidraCxxProfile.inspect(reopened, "not-a-match", MONITOR).get("selection")).equals(text),
                    "immutable inventory survives reopen exactly");
                require(records(reopened).equals(committed), "immutable metadata unchanged");
            }
            finally { if (reopened == null) handle.close(); else reopened.release(reopenedConsumer); }
            require(Arrays.equals(hash, digest(saved)) && stamp.equals(Files.getLastModifiedTime(saved)), "inventory preserves on-disk database and timestamp");
        }
        finally {
            program.release(consumer);
            Files.deleteIfExists(selected); Files.deleteIfExists(saved); Files.deleteIfExists(directory);
        }
    }

    private static void parserControls(Path path, String valid) throws Exception {
        var source = JsonParser.parseString(valid).getAsJsonObject();
        var invalid = new ArrayList<String>();
        invalid.add(valid + "{}"); invalid.add(valid.replace("\"schema\":1", "\"schema\":2"));
        invalid.add(valid.replace("\"schema\":1", "\"schema\":1,\"sch\\u0065ma\":1"));
        var changed = source.deepCopy(); changed.addProperty("extra", "unknown"); invalid.add(changed.toString());
        for (String key : source.keySet()) { changed = source.deepCopy(); changed.remove(key); invalid.add(changed.toString()); }
        for (String spelling : List.of("01", "1e3", "-0", "9223372036854775808", " 1")) {
            changed = source.deepCopy(); changed.addProperty("program_id", spelling); invalid.add(changed.toString());
        }
        changed = source.deepCopy(); changed.addProperty("program_id", 123); invalid.add(changed.toString());
        changed = source.deepCopy(); changed.addProperty("abi", "UNSPECIFIED"); invalid.add(changed.toString());
        changed = source.deepCopy(); changed.addProperty("inheritance_mode", "merge"); invalid.add(changed.toString());
        changed = source.deepCopy(); changed.getAsJsonArray("classes").add(changed.getAsJsonArray("classes").get(0).deepCopy()); invalid.add(changed.toString());
        for (String spelling : List.of("0", "-1")) {
            changed = source.deepCopy(); changed.getAsJsonArray("classes").get(0).getAsJsonObject().addProperty("class_id", spelling); invalid.add(changed.toString());
        }
        changed = source.deepCopy(); changed.getAsJsonObject("remove").getAsJsonArray("classes").add(
            source.getAsJsonArray("classes").get(0).getAsJsonObject().get("class_id")); invalid.add(changed.toString());
        // A location is a tagged union: do not accept mixed, missing or foreign geometry fields.
        for (String location : List.of(
                "{\"kind\":\"fixed\",\"offset\":\"0\"}",
                "{\"kind\":\"fixed\",\"offset\":\"0\",\"occupied_bytes\":\"4\",\"slot_offset\":\"-24\"}",
                "{\"kind\":\"virtual\",\"vptr_offset\":\"0\"}",
                "{\"kind\":\"virtual\",\"vptr_offset\":\"0\",\"slot_offset\":-24}")) {
            changed = source.deepCopy();
            var base = JsonParser.parseString("{\"derived_class_id\":\"1\",\"base_class_id\":\"2\",\"order\":0,\"access\":\"PUBLIC\",\"evidence\":\"control\"}").getAsJsonObject();
            base.add("location", JsonParser.parseString(location)); changed.getAsJsonArray("bases").add(base); invalid.add(changed.toString());
        }
        changed = source.deepCopy(); changed.getAsJsonArray("classes").get(0).getAsJsonObject().addProperty("evidence", "x".repeat(8193)); invalid.add(changed.toString());
        invalid.add(" ".repeat(1024 * 1024) + valid);
        for (String bad : invalid) {
            Files.writeString(path, bad);
            try { CxxSelection.read(path, () -> false); throw new AssertionError("invalid JSON accepted: " + bad.substring(0, Math.min(100, bad.length()))); }
            catch (IOException expected) { checks++; }
        }
        Files.write(path, new byte[] {(byte) 0xc3, (byte) 0x28});
        try { CxxSelection.read(path, () -> false); throw new AssertionError("malformed UTF-8 accepted"); }
        catch (IOException expected) { checks++; }
        Files.writeString(path, valid);
        try { CxxSelection.read(path, () -> true); throw new AssertionError("parser ignored cancellation"); }
        catch (java.util.concurrent.CancellationException expected) { checks++; }
    }

    private static CxxSelection copy(CxxSelection source, List<GhidraVtableBindings.Request> tables, CxxSelection.Removals remove) {
        return new CxxSelection(source.programId(), source.language(), source.compiler(), source.classes(), source.declarations(), source.inheritance(), tables, remove);
    }

    private static Map<String, String> records(Program program) {
        var result = new TreeMap<String, String>();
        for (String group : List.of(GhidraClassBindings.OPTIONS_NAME, GhidraDeclarationBindings.OPTIONS_NAME,
                GhidraInheritanceBindings.OPTIONS_NAME, GhidraVtableBindings.OPTIONS_NAME)) {
            if (!program.getOptionsNames().contains(group)) continue;
            var options = program.getOptions(group);
            for (String key : options.getOptionNames()) result.put(group + "/" + key, options.getString(key, null));
        }
        return result;
    }

    private static String physical(Program program) throws Exception {
        var result = new StringBuilder(program.getOptions("Analyst").getString("keep", ""));
        var symbols = program.getSymbolTable().getAllSymbols(true);
        while (symbols.hasNext()) {
            var symbol = symbols.next(); result.append('|').append(symbol.getID()).append(':').append(symbol.getName(true)).append('@').append(symbol.getAddress());
            if (symbol.getObject() instanceof Function function) result.append(function.getPrototypeString(true, true));
        }
        var structures = program.getDataTypeManager().getAllStructures();
        while (structures.hasNext()) { var type = structures.next(); result.append('|').append(type.getPathName()).append(':').append(type.getLength()); }
        byte[] memory = new byte[4]; program.getMemory().getBytes(program.getMinAddress(), memory); result.append(Arrays.toString(memory));
        return result.toString();
    }

    private static byte[] digest(Path path) throws Exception { return MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path)); }
    private interface Operation { void run() throws Exception; }
    private static void rejects(Operation operation) throws Exception {
        try { operation.run(); throw new AssertionError("invalid configuration accepted"); }
        catch (IllegalArgumentException expected) { checks++; }
    }
    private static void require(boolean value, String message) { if (!value) throw new AssertionError(message); checks++; }
}
