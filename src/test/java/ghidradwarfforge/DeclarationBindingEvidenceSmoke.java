package ghidradwarfforge;

import java.io.File;
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
import ghidradwarfforge.GhidraDeclarationBindings.*;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.InheritanceModel;
import ghidradwarfforge.types.InheritanceModel.*;
import ghidradwarfforge.targets.CxxAbiProfile;

/** Explicit mixed method ownership, stale evidence and immutable production extraction. */
public final class DeclarationBindingEvidenceSmoke {
    private static int checks;
    private static final TaskMonitor MONITOR = TaskMonitor.DUMMY;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (String[] profile : List.of(new String[] {"x86:LE:64:default", "x86_64"},
                new String[] {"AARCH64:LE:64:v8A", "aarch64"}, new String[] {"ARM:LE:32:v8", "arm"},
                new String[] {"MIPS:BE:32:default", "mips"}, new String[] {"MIPS:LE:32:default", "mipsel"})) {
            check(profile[0], profile[1]);
        }
        System.out.println("declaration-binding-evidence=PASS checks=" + checks);
    }

    private static void check(String languageId, String target) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(languageId));
        Object token = new Object();
        var program = new ProgramDB("mixed-methods", language, language.getDefaultCompilerSpec(), token);
        var directory = Files.createTempDirectory("forge-declaration-");
        var saved = directory.resolve("program.db");
        Binding binding;
        long originalParent;
        try {
            require(GhidraDeclarationBindings.read(program, 123, MONITOR, ignored -> { }).status() == Status.ABSENT,
                "absent evidence");
            require(!program.getOptionsNames().contains(GhidraDeclarationBindings.OPTIONS_NAME), "absence creates no options");
            int tx = program.startTransaction("explicit mixed-method fixture");
            try {
                var table = program.getSymbolTable();
                var owner = table.createClass(program.getGlobalNamespace(), "Mixed", SourceType.USER_DEFINED);
                var layout = new StructureDataType("Mixed", 0);
                layout.add(IntegerDataType.dataType, "value", "fixture layout");
                var structure = (Structure) program.getDataTypeManager().addDataType(layout, DataTypeConflictHandler.DEFAULT_HANDLER);
                GhidraClassBindings.save(program, owner, structure, "explicit fixture canonical class", MONITOR);
                var address = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x401000);
                program.getMemory().createInitializedBlock("body", address, 4, (byte) 0, MONITOR, false);
                var local = program.getFunctionManager().createFunction("implemented", owner, address,
                    new AddressSet(address, address.add(3)), SourceType.USER_DEFINED);
                local.setCallingConvention("__thiscall");
                local.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
                var library = program.getExternalManager().addExternalLibraryName("Declarations", SourceType.USER_DEFINED);
                var externalOwner = table.createClass(library, "Mixed", SourceType.USER_DEFINED);
                var declared = program.getExternalManager().addExtFunction(externalOwner, "declared", null, SourceType.USER_DEFINED).getFunction();
                declared.setCallingConvention("__thiscall");
                declared.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
                originalParent = declared.getParentNamespace().getID();
                binding = new Binding(declared.getID(), owner.getID(), "analyst confirms declaration belongs to canonical Mixed");
                GhidraDeclarationBindings.save(program, binding, MONITOR);
                require(read(program, binding).status() == Status.VALID, "roundtrip binding");
                var options = program.getOptions(GhidraDeclarationBindings.OPTIONS_NAME);
                String key = "method-" + binding.methodId(), encoded = options.getString(key, null);
                GhidraDeclarationBindings.save(program, binding, MONITOR);
                require(encoded.equals(options.getString(key, null)), "deterministic save");
                if (target.equals("x86_64") || target.equals("aarch64")) {
                    var abi = target.equals("x86_64") ? CxxAbiProfile.ITANIUM_X86_64 : CxxAbiProfile.ITANIUM_AARCH64;
                    var inheritance = new InheritanceModel(abi, List.of(), List.of(
                        new VirtualMethod(local.getID(), 0, Access.PUBLIC, Virtuality.VIRTUAL, "local slot fixture"),
                        new VirtualMethod(declared.getID(), 1, Access.PUBLIC, Virtuality.PURE_VIRTUAL, "addressless slot fixture")));
                    GhidraInheritanceBindings.save(program, inheritance, MONITOR);
                    require(extract(program, target).classScopes().inheritance().equals(inheritance), "mixed virtual ownership extracted");
                }
                mixed(program, target, binding, originalParent);
                rejects(() -> GhidraDeclarationBindings.save(program, new Binding(local.getID(), owner.getID(), "not addressless"), MONITOR));
                var cancel = new TaskMonitorAdapter(true); cancel.cancel();
                try { GhidraDeclarationBindings.save(program, binding, cancel); throw new AssertionError("ignored cancellation"); }
                catch (CancelledException expected) { checks++; }
                require(encoded.equals(options.getString(key, null)), "cancelled save preserves record");
                var midCancel = new TaskMonitorAdapter(true) {
                    private int visits;
                    @Override public void checkCancelled() throws CancelledException {
                        if (++visits == 8) throw new CancelledException();
                    }
                };
                try { GhidraDeclarationBindings.save(program, binding, midCancel); throw new AssertionError("ignored mid-snapshot cancellation"); }
                catch (CancelledException expected) { checks++; }
                require(encoded.equals(options.getString(key, null)), "mid-snapshot cancellation preserves record");
                for (String bad : List.of("bad", "GDFMD1:!", encoded + "AAAA", "GDFMD1:" + "A".repeat(50000))) {
                    options.setString(key, bad);
                    require(read(program, binding).status() == Status.REJECTED, "malformed binding rejected");
                    require(bad.equals(options.getString(key, null)), "rejected record unchanged");
                }
                options.setString(key, encoded);
                declared.setReturnType(LongLongDataType.dataType, SourceType.USER_DEFINED);
                require(read(program, binding).status() == Status.REJECTED, "signature change rejected");
                var rejected = extract(program, target);
                require(rejected.classScopes().methods().stream().noneMatch(m -> m.id() == binding.methodId()), "rejection does not infer another owner");
                require(rejected.functionDeclarations().stream().anyMatch(d -> d.key().equals("external:" + binding.methodId())),
                    "independent addressless signature retained");
                require(rejected.classScopes().inheritance().virtualMethods().isEmpty(), "stale association cannot retain virtual relationships");
                declared.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
                structure.add(IntegerDataType.dataType, "new_member", "");
                require(read(program, binding).status() == Status.REJECTED, "physical class change rejected");
                structure.delete(structure.getNumComponents() - 1);
                require(read(program, binding).status() == Status.VALID, "restoration recovers exact snapshot");
                GhidraClassBindings.remove(program, owner.getID(), MONITOR);
                require(read(program, binding).status() == Status.REJECTED, "missing canonical class rejected");
                GhidraClassBindings.save(program, owner, structure, "restored canonical identity", MONITOR);
                declared.setName("renamed_declaration", SourceType.USER_DEFINED);
                require(read(program, binding).status() == Status.VALID, "identity-preserving rename allowed");
                var other = table.createClass(library, "Different", SourceType.USER_DEFINED);
                declared.setParentNamespace(other);
                require(read(program, binding).status() == Status.REJECTED, "changed declaration namespace rejected");
                declared.setParentNamespace(externalOwner);
                require(read(program, binding).status() == Status.VALID, "namespace restoration");
                options.removeOption(key); options.setInt(key, 1);
                require(read(program, binding).status() == Status.REJECTED, "wrong option type rejected");
                rejects(() -> GhidraDeclarationBindings.save(program, binding, MONITOR));
                options.removeOption(key); options.setString(key, encoded);
                var wrongClass = table.createClass(program.getGlobalNamespace(), "Wrong", SourceType.USER_DEFINED);
                var wrongType = (Structure) program.getDataTypeManager().addDataType(new StructureDataType("Wrong", 4), DataTypeConflictHandler.DEFAULT_HANDLER);
                GhidraClassBindings.save(program, wrongClass, wrongType, "wrong class control", MONITOR);
                rejects(() -> GhidraDeclarationBindings.save(program, new Binding(binding.methodId(), wrongClass.getID(), "mismatched object control"), MONITOR));
                GhidraClassBindings.remove(program, wrongClass.getID(), MONITOR);
                GhidraDeclarationBindings.remove(program, binding.methodId(), MONITOR);
                require(read(program, binding).status() == Status.ABSENT, "explicit removal");
                require(extract(program, target).classScopes().methods().stream().anyMatch(m ->
                    m.id() == binding.methodId() && m.classId() == originalParent), "absence preserves original saved ownership");
                GhidraDeclarationBindings.save(program, binding, MONITOR);
                owner.getSymbol().setName("RecoveredMixed", SourceType.USER_DEFINED);
                structure.setName("RecoveredMixed");
                externalOwner.getSymbol().setName("RecoveredMixed", SourceType.USER_DEFINED);
                require(read(program, binding).status() == Status.VALID, "coordinated canonical and external class rename");
                program.setImageBase(program.getImageBase().add(0x200000), true);
                require(read(program, binding).status() == Status.VALID, "image rebase preserves addressless identity");
                mixed(program, target, binding, originalParent);
            }
            finally { program.endTransaction(tx, true); }
            program.getDBHandle().saveAs(saved.toFile(), false, MONITOR);
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(saved));
            var timestamp = Files.getLastModifiedTime(saved);
            var handle = new DBHandle(saved.toFile());
            Object reopenedToken = new Object();
            ProgramDB reopened = null;
            try {
                reopened = new ProgramDB(handle, OpenMode.IMMUTABLE, MONITOR, reopenedToken);
                require(read(reopened, binding).status() == Status.VALID, "immutable binding read");
                mixed(reopened, target, binding, originalParent);
                mixed(reopened, target, binding, originalParent);
            }
            finally { if (reopened != null) reopened.release(reopenedToken); else handle.close(); }
            require(Arrays.equals(hash, MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(saved))) &&
                timestamp.equals(Files.getLastModifiedTime(saved)), "immutable extraction preserves database");
        }
        finally {
            program.release(token);
            Files.deleteIfExists(saved); Files.deleteIfExists(directory);
        }
    }

    private static Result read(Program program, Binding binding) throws Exception {
        return GhidraDeclarationBindings.read(program, binding.methodId(), MONITOR, ignored -> { });
    }

    private static ProgramTypeModel extract(Program program, String target) throws Exception {
        var functions = new ArrayList<FunctionSymbol>();
        for (var function : program.getFunctionManager().getFunctions(true)) {
            functions.add(new FunctionSymbol(function.getName(true), function.getEntryPoint().getOffset(), function.getBody().getNumAddresses()));
        }
        return GhidraTypeGraph.extract(program, functions, target, 0, MONITOR, ignored -> { });
    }

    private static void mixed(Program program, String target, Binding binding, long parent) throws Exception {
        var model = extract(program, target);
        var methods = model.classScopes().methods().stream().filter(m -> m.classId() == binding.classId()).toList();
        require(methods.size() == 2, "one canonical class has both methods: " + model.classScopes().methods());
        var declaration = methods.stream().filter(m -> m.id() == binding.methodId()).findFirst().orElseThrow();
        require(declaration.function().address() == -1 && !declaration.function().declarationKey().isEmpty(), "no invented declaration address");
        require(model.classScopes().bindings().size() == 1, "one canonical layout");
        require(program.getSymbolTable().getSymbol(binding.methodId()).getParentNamespace().getID() == parent, "original Ghidra namespace preserved");
    }

    private interface Operation { void run() throws Exception; }
    private static void rejects(Operation operation) throws Exception {
        try { operation.run(); throw new AssertionError("invalid save accepted"); }
        catch (IllegalArgumentException expected) { checks++; }
    }
    private static void require(boolean value, String message) {
        checks++; if (!value) throw new AssertionError(message);
    }
}
