package ghidradwarfforge;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.file.Files;
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
import ghidradwarfforge.targets.CxxAbiProfile;
import ghidradwarfforge.types.InheritanceModel;
import ghidradwarfforge.types.InheritanceModel.*;
import ghidradwarfforge.GhidraInheritanceBindings.Status;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.types.ProgramTypeModel;

/** Real saved programs: geometry, identity, malformed records, cancellation and immutable reopening. */
public final class InheritanceBindingEvidenceSmoke {
    private static int checks;
    private static final String GROUP = GhidraInheritanceBindings.OPTIONS_NAME;
    private static final String KEY = GhidraInheritanceBindings.KEY;
    private static final TaskMonitor MONITOR = TaskMonitor.DUMMY;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        check("x86:LE:64:default", CxxAbiProfile.ITANIUM_X86_64);
        check("AARCH64:LE:64:v8A", CxxAbiProfile.ITANIUM_AARCH64);
        System.out.println("inheritance-binding-evidence=PASS checks=" + checks);
    }

    private static void check(String languageId, CxxAbiProfile abi) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(languageId));
        Object token = new Object();
        var program = new ProgramDB("inheritance", language, language.getDefaultCompilerSpec(), token);
        var foreign = new ProgramDB("foreign", language, language.getDefaultCompilerSpec(), token);
        var directory = Files.createTempDirectory("forge-inheritance-binding-");
        var saved = directory.resolve("program.db");
        InheritanceModel model;
        String encoded;
        long methodId;
        try {
            int transaction = program.startTransaction("binding tests");
            try {
                require(read(program).status() == Status.ABSENT, "absent evidence");
                GhidraInheritanceBindings.remove(program, MONITOR);
                require(!program.getOptionsNames().contains(GROUP), "absent read/remove created options");
                var symbols = program.getSymbolTable();
                var baseClass = symbols.createClass(program.getGlobalNamespace(), "Base", SourceType.USER_DEFINED);
                var childClass = symbols.createClass(program.getGlobalNamespace(), "Child", SourceType.USER_DEFINED);
                var base = structure(program, "BaseLayout", 16);
                var entry = language.getDefaultSpace().getAddress(0x401000);
                program.getMemory().createInitializedBlock("text", entry, 16, (byte) 0, MONITOR, false);
                var method = program.getFunctionManager().createFunction("inspect", entry,
                    new AddressSet(entry, entry.add(3)), SourceType.USER_DEFINED);
                method.setParentNamespace(childClass);
                method.setCallingConvention("__thiscall");
                method.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
                methodId = method.getID();
                var object = Arrays.stream(method.getParameters()).filter(p -> p.getAutoParameterType() == AutoParameterType.THIS)
                    .findFirst().orElseThrow();
                var child = (Structure) ((Pointer) object.getFormalDataType()).getDataType();
                var nested = structure(program, "Nested", 8);
                child.add(new ArrayDataType(ByteDataType.dataType, 16, 1), "header", "");
                child.add(nested, "nested", "");
                child.add(new PointerDataType(child, 8, program.getDataTypeManager()), "self", "");
                require(child.getLength() == 32, "fixture child extent");
                GhidraClassBindings.save(program, baseClass, base, "base identity", MONITOR);
                GhidraClassBindings.save(program, childClass, child, "child identity", MONITOR);
                model = new InheritanceModel(abi, List.of(new Base(childClass.getID(), baseClass.getID(), 0,
                    Access.PUBLIC, new FixedBase(0, 16), "analyst base evidence")),
                    List.of(new VirtualMethod(methodId, 0, Access.PUBLIC, Virtuality.VIRTUAL, "analyst slot evidence")));
                for (int stop : List.of(1, 5)) {
                    cancelled(() -> GhidraInheritanceBindings.save(program, model, cancelAt(stop)));
                    require(!program.getOptionsNames().contains(GROUP), "cancelled initial save created options");
                }
                var excessive = new ArrayList<Base>();
                for (int id = 2; id < 4099; id++) excessive.add(new Base(id, 1, 0, Access.PUBLIC,
                    new FixedBase(0, 0), "bounded record control"));
                var oversized = new InheritanceModel(abi, excessive, List.of());
                rejects(() -> GhidraInheritanceBindings.save(program, oversized, MONITOR));
                require(!program.getOptionsNames().contains(GROUP), "oversized save created options");
                GhidraInheritanceBindings.save(program, model, MONITOR);
                var options = program.getOptions(GROUP);
                encoded = options.getString(KEY, null);
                require(read(program).model().equals(model), "saved relationship round trip");
                require(extract(program, abi, true, new ArrayList<>(), MONITOR).classScopes().inheritance().equals(model),
                    "production extraction lost saved relationships");
                var partialMessages = new ArrayList<String>();
                require(extract(program, abi, false, partialMessages, MONITOR).classScopes().inheritance().equals(InheritanceModel.empty()),
                    "partial export retained unavailable virtual method");
                require(partialMessages.stream().anyMatch(s -> s.startsWith("Omitted explicit inheritance from this export")),
                    "partial export did not diagnose omitted relationships");
                require(encoded.equals(options.getString(KEY, null)), "partial export changed saved evidence");
                var competingClass = symbols.createClass(program.getGlobalNamespace(), "CompetingBase", SourceType.USER_DEFINED);
                GhidraClassBindings.save(program, competingClass, base, "competing canonical layout", MONITOR);
                require(read(program).status() == Status.VALID, "unrelated class changed saved snapshot");
                var conflictMessages = new ArrayList<String>();
                require(extract(program, abi, true, conflictMessages, MONITOR).classScopes().inheritance().equals(InheritanceModel.empty()),
                    "conflicting canonical layout admitted inheritance");
                require(conflictMessages.stream().anyMatch(s -> s.startsWith("Omitted explicit inheritance from this export")),
                    "canonical conflict lacks inheritance diagnostic");
                GhidraClassBindings.remove(program, competingClass.getID(), MONITOR);
                int[] visits = { 0 };
                var count = new TaskMonitorAdapter(true) {
                    @Override public void checkCancelled() { visits[0]++; }
                };
                GhidraInheritanceBindings.save(program, model, count);
                for (int stop : List.of(1, visits[0] / 2, visits[0])) {
                    cancelled(() -> GhidraInheritanceBindings.save(program, model, cancelAt(stop)));
                    require(encoded.equals(options.getString(KEY, null)), "cancel changed prior record");
                }
                visits[0] = 0;
                GhidraInheritanceBindings.read(program, count, ignored -> { });
                for (int stop : List.of(1, visits[0] / 2, visits[0])) {
                    cancelled(() -> GhidraInheritanceBindings.read(program, cancelAt(stop), ignored -> { }));
                    require(encoded.equals(options.getString(KEY, null)), "cancelled read repaired record");
                }
                visits[0] = 0;
                extract(program, abi, true, new ArrayList<>(), count);
                for (int stop : List.of(1, visits[0] / 2, visits[0])) {
                    cancelled(() -> extract(program, abi, true, new ArrayList<>(), cancelAt(stop)));
                    require(encoded.equals(options.getString(KEY, null)), "cancelled extraction changed evidence");
                }
                base.setName("RenamedBaseLayout"); base.setCategoryPath(new CategoryPath("/renamed"));
                child.getDefinedComponents()[0].setFieldName("renamedMember");
                method.setName("renamedMethod", SourceType.USER_DEFINED);
                program.setImageBase(entry.add(0x200000), true);
                require(read(program).model().equals(model), "rename or rebase invalidated stable geometry");
                require(extract(program, abi, true, new ArrayList<>(), MONITOR).classScopes().inheritance().equals(model),
                    "rename or rebase changed extracted relationships");
                GhidraInheritanceBindings.save(program, model, MONITOR);
                require(encoded.equals(options.getString(KEY, null)), "renames/rebase changed serialized evidence");
                nested.replaceAtOffset(0, UnsignedIntegerDataType.dataType, 4, "changed", "");
                rejected(program);
                var staleMessages = new ArrayList<String>();
                var staleModel = extract(program, abi, true, staleMessages, MONITOR);
                require(staleModel.classScopes().inheritance().equals(InheritanceModel.empty()) &&
                    staleModel.classScopes().methods().size() == 1 && staleModel.classScopes().bindings().size() == 2,
                    "stale inheritance lost independently valid ownership/layouts or inferred relationships");
                require(staleMessages.stream().anyMatch(s -> s.startsWith("Omitted explicit inheritance:")),
                    "stale extraction lacks diagnostic");
                require(encoded.equals(options.getString(KEY, null)), "stale extraction repaired saved record");
                nested.replaceAtOffset(0, IntegerDataType.dataType, 4, "restored", "");
                require(read(program).status() == Status.VALID, "restored nested geometry did not recover");
                child.growStructure(1); rejected(program);
                child.deleteAtOffset(child.getLength() - 1);
                require(read(program).status() == Status.VALID, "restored outer geometry did not recover");
                method.setParentNamespace(program.getGlobalNamespace()); rejected(program);
                method.setParentNamespace(childClass);
                require(read(program).status() == Status.VALID, "restored method owner did not recover");
                method.setReturnType(UnsignedIntegerDataType.dataType, SourceType.USER_DEFINED); rejected(program);
                method.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
                require(read(program).status() == Status.VALID, "restored method signature");
                var wrongAbi = new InheritanceModel(abi == CxxAbiProfile.ITANIUM_X86_64 ?
                    CxxAbiProfile.ITANIUM_AARCH64 : CxxAbiProfile.ITANIUM_X86_64, model.bases(), model.virtualMethods());
                rejects(() -> GhidraInheritanceBindings.save(program, wrongAbi, MONITOR));
                require(encoded.equals(options.getString(KEY, null)), "wrong target changed prior binding");
                byte[] raw = Base64.getDecoder().decode(encoded.substring("GDFIB1:".length()));
                var malformed = new ArrayList<String>(List.of("", "GDFIB1:!", "GDFIB2:AA==", encoded + "AA==",
                    "GDFIB1:" + "A".repeat(1400000)));
                var cursor = new ByteArrayInputStream(raw);
                var fields = new DataInputStream(cursor);
                fields.readInt(); fields.readLong(); fields.readUTF(); fields.readUTF(); fields.readUTF();
                int countOffset = raw.length - cursor.available();
                for (int invalidCount : List.of(-1, 4097)) {
                    byte[] bad = raw.clone(); ByteBuffer.wrap(bad).putInt(countOffset, invalidCount);
                    malformed.add("GDFIB1:" + Base64.getEncoder().encodeToString(bad));
                }
                for (int length : List.of(0, 4, 12, raw.length - 1)) {
                    malformed.add("GDFIB1:" + Base64.getEncoder().encodeToString(Arrays.copyOf(raw, length)));
                }
                for (int offset : List.of(0, 4, raw.length - 1)) {
                    byte[] bad = raw.clone(); bad[offset] ^= 1;
                    malformed.add("GDFIB1:" + Base64.getEncoder().encodeToString(bad));
                }
                for (String bad : malformed) {
                    options.setString(KEY, bad); rejected(program);
                    require(bad.equals(options.getString(KEY, null)), "rejected evidence repaired");
                }
                options.setString(KEY, encoded);
                int foreignTx = foreign.startTransaction("foreign record");
                try { foreign.getOptions(GROUP).setString(KEY, encoded); rejected(foreign); }
                finally { foreign.endTransaction(foreignTx, true); }
                options.removeOption(KEY); options.setInt(KEY, 23); rejected(program);
                rejects(() -> GhidraInheritanceBindings.save(program, model, MONITOR));
                require(options.getInt(KEY, 0) == 23, "foreign option kind changed");
                options.removeOption(KEY); options.setString(KEY, encoded);
                GhidraClassBindings.remove(program, baseClass.getID(), MONITOR); rejected(program);
                GhidraClassBindings.save(program, baseClass, base, "base identity", MONITOR);
                require(read(program).status() == Status.VALID, "restored explicit type binding");
                var virtual = new InheritanceModel(abi, List.of(new Base(childClass.getID(), baseClass.getID(), 0,
                    Access.PROTECTED, new VirtualBase(0, -24), "explicit virtual offset")), model.virtualMethods());
                GhidraInheritanceBindings.save(program, virtual, MONITOR);
                require(read(program).model().equals(virtual), "virtual base round trip");
                GhidraInheritanceBindings.save(program, model, MONITOR);
                require(encoded.equals(options.getString(KEY, null)), "deterministic explicit restoration");
            }
            finally { program.endTransaction(transaction, true); }
            program.getDBHandle().saveAs(saved.toFile(), false, MONITOR);
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(saved));
            var timestamp = Files.getLastModifiedTime(saved);
            Object reopenedToken = new Object();
            var handle = new DBHandle(saved.toFile());
            ProgramDB reopened = null;
            try {
                reopened = new ProgramDB(handle, OpenMode.IMMUTABLE, MONITOR, reopenedToken);
                require(read(reopened).model().equals(model), "immutable reopening lost snapshot");
                require(read(reopened).model().equals(model), "repeated immutable read differs");
                require(extract(reopened, abi, true, new ArrayList<>(), MONITOR).classScopes().inheritance().equals(model),
                    "immutable production extraction lost relationships");
            }
            finally { if (reopened != null) reopened.release(reopenedToken); else handle.close(); }
            require(Arrays.equals(hash, MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(saved))) &&
                timestamp.equals(Files.getLastModifiedTime(saved)), "immutable read changed database");
            int renamedObject = program.startTransaction("automatic THIS replacement control");
            try {
                var method = (Function) program.getSymbolTable().getSymbol(methodId).getObject();
                long owner = method.getParentNamespace().getID();
                var binding = GhidraClassBindings.read(program, owner, MONITOR, ignored -> { }).binding();
                binding.type().setName("DifferentAutomaticLookup");
                rejected(program); // Ghidra now supplies another automatic THIS type.
            }
            finally { program.endTransaction(renamedObject, false); }
            require(read(program).status() == Status.VALID, "rolled-back automatic THIS replacement");
            int deletion = program.startTransaction("deleted method control");
            try {
                var symbol = program.getSymbolTable().getSymbol(methodId);
                var method = (Function) symbol.getObject();
                program.getFunctionManager().removeFunction(method.getEntryPoint());
                rejected(program);
            }
            finally { program.endTransaction(deletion, true); }
            System.out.println("inheritance-binding-target=PASS " + languageId);
        }
        finally {
            program.release(token); foreign.release(token);
            Files.deleteIfExists(saved); Files.deleteIfExists(directory);
        }
    }

    private static Structure structure(Program program, String name, int size) {
        var type = new StructureDataType(name, 0);
        for (int i = 0; i < size / 4; i++) type.add(IntegerDataType.dataType, "field" + i, "");
        return (Structure) program.getDataTypeManager().addDataType(type, DataTypeConflictHandler.DEFAULT_HANDLER);
    }
    private static ProgramTypeModel extract(Program program, CxxAbiProfile abi, boolean includeMethods,
            List<String> messages, TaskMonitor monitor) throws Exception {
        var functions = new ArrayList<FunctionSymbol>();
        if (includeMethods) {
            for (var function : program.getFunctionManager().getFunctions(true)) {
                functions.add(new FunctionSymbol(function.getName(true), function.getEntryPoint().getOffset(),
                    function.getBody().getNumAddresses()));
            }
        }
        return GhidraTypeGraph.extract(program, functions,
            abi == CxxAbiProfile.ITANIUM_X86_64 ? "x86_64" : "aarch64", 0, monitor, messages::add);
    }
    private static GhidraInheritanceBindings.Result read(Program program) throws Exception {
        var messages = new ArrayList<String>();
        var result = GhidraInheritanceBindings.read(program, MONITOR, messages::add);
        if (result.status() == Status.REJECTED) throw new AssertionError(messages.toString());
        return result;
    }
    private static void rejected(Program program) throws Exception {
        var messages = new ArrayList<String>();
        var result = GhidraInheritanceBindings.read(program, MONITOR, messages::add);
        require(result.status() == Status.REJECTED && result.model() == null && messages.size() == 1, "invalid evidence not rejected: " + messages);
    }
    private static TaskMonitor cancelAt(int count) {
        return new TaskMonitorAdapter(true) {
            private int visits;
            @Override public void checkCancelled() throws CancelledException {
                if (++visits == count) throw new CancelledException();
            }
        };
    }
    private interface Operation { void run() throws Exception; }
    private static void cancelled(Operation operation) throws Exception {
        try { operation.run(); throw new AssertionError("cancellation ignored"); }
        catch (CancelledException expected) { checks++; }
    }
    private static void rejects(Operation operation) throws Exception {
        try { operation.run(); throw new AssertionError("invalid save accepted"); }
        catch (IllegalArgumentException expected) { checks++; }
    }
    private static void require(boolean value, String message) {
        checks++; if (!value) throw new AssertionError(message);
    }
}
