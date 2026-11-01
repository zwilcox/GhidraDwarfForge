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
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.AutoParameterType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.types.ClassScopeModel;
import ghidradwarfforge.types.ClassScopeModel.BindingSource;
import ghidradwarfforge.types.ProgramTypeModel;

/** Production extraction from actual ProgramDB ownership and automatic object types. */
public final class ClassScopeExtractionSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (String[] profile : List.of(new String[] {"x86:LE:64:default", "x86_64"},
                new String[] {"AARCH64:LE:64:v8A", "aarch64"}, new String[] {"ARM:LE:32:v8", "arm"},
                new String[] {"MIPS:BE:32:default", "mips"}, new String[] {"MIPS:LE:32:default", "mipsel"})) {
            check(profile[0], profile[1]);
        }
        System.out.println("class-scope-extraction=PASS checks=" + checks);
    }

    private static void check(String languageId, String target) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(languageId));
        Object token = new Object();
        var program = new ProgramDB("class-scopes", language, language.getDefaultCompilerSpec(), token);
        var directory = Files.createTempDirectory("forge-class-scopes-");
        var saved = directory.resolve("program.db");
        var diagnostics = new ArrayList<String>();
        List<FunctionSymbol> symbols;
        ClassScopeModel expected;
        try {
            int tx = program.startTransaction("scope evidence fixture");
            try {
                var table = program.getSymbolTable();
                var namespace = table.createNameSpace(program.getGlobalNamespace(), "outer", SourceType.USER_DEFINED);
                var owner = table.createClass(namespace, "Counter", SourceType.USER_DEFINED);
                var method = method(program, owner, "inspect", 0x401000);
                method.setCallingConvention("__thiscall");
                var object = Arrays.stream(method.getParameters()).filter(p -> p.getAutoParameterType() == AutoParameterType.THIS)
                    .findFirst().orElseThrow(() -> new AssertionError("no THIS on " + languageId));
                require(object.getFormalDataType() instanceof Pointer, "automatic object pointer");
                var layout = (Structure) ((Pointer) object.getFormalDataType()).getDataType();
                symbols = List.of(new FunctionSymbol(method.getName(true), 0x401000, 4));
                var placeholder = extract(program, symbols, target, 0, diagnostics);
                require(placeholder.classScopes().methods().size() == 1 && placeholder.classScopes().bindings().isEmpty(),
                    "placeholder preserves ownership without inventing layout");
                require(diagnostics.stream().anyMatch(s -> s.contains("no evidenced member layout")), "placeholder diagnostic");
                layout.add(IntegerDataType.dataType, "value", "analyst recovered member");
                var inferred = extract(program, symbols, target, 0, diagnostics);
                require(binding(inferred, owner.getID()).source() == BindingSource.CURRENT_AUTO_THIS, "current object inference provenance");
                require(inferred.classScopes().scopes().size() == 2 && inferred.classScopes().scopes().get(1).parent() == namespace.getID(),
                    "recorded namespace parent");
                GhidraClassBindings.save(program, owner, layout, "explicit current object layout", TaskMonitor.DUMMY);
                var explicit = extract(program, symbols, target, 0, diagnostics);
                require(binding(explicit, owner.getID()).source() == BindingSource.EXPLICIT_SAVED, "explicit evidence precedes inference");
                String original = program.getOptions(GhidraClassBindings.OPTIONS_NAME).getString("class-" + owner.getID(), null);
                program.getOptions(GhidraClassBindings.OPTIONS_NAME).setString("class-" + owner.getID(), "GDFCB1:!");
                var stale = extract(program, symbols, target, 0, diagnostics);
                require(stale.classScopes().bindings().isEmpty() && stale.classScopes().methods().size() == 1,
                    "rejected explicit record must not fall back to valid THIS inference");
                require(diagnostics.stream().anyMatch(s -> s.startsWith("Omitted explicit class binding")), "stale diagnostic");
                program.getOptions(GhidraClassBindings.OPTIONS_NAME).setString("class-" + owner.getID(), original);
                var otherLayout = new StructureDataType(new CategoryPath("/distinct"), layout.getName(), 0);
                otherLayout.add(IntegerDataType.dataType, "other", "distinct same-name identity");
                otherLayout.add(IntegerDataType.dataType, "extra", "different layout");
                var distinct = (Structure) program.getDataTypeManager().addDataType(otherLayout, DataTypeConflictHandler.DEFAULT_HANDLER);
                GhidraClassBindings.save(program, owner, distinct, "contradictory current object", TaskMonitor.DUMMY);
                var conflict = extract(program, symbols, target, 0, diagnostics);
                require(conflict.classScopes().bindings().isEmpty() && conflict.classScopes().methods().size() == 1,
                    "conflicting layout does not change object or method identity");
                require(conflict.functions().getFirst().parameters().equals(explicit.functions().getFirst().parameters()),
                    "conflict preserves exact current object type");
                require(diagnostics.stream().anyMatch(s -> s.contains("contradict")), "conflicting object diagnostic");
                GhidraClassBindings.save(program, owner, layout, "explicit current object layout", TaskMonitor.DUMMY);
                var otherOwner = table.createClass(namespace, "StaticOnly", SourceType.USER_DEFINED);
                GhidraClassBindings.save(program, otherOwner, layout, "conflicting explicit owner", TaskMonitor.DUMMY);
                var duplicate = extract(program, symbols, target, 0, diagnostics);
                require(duplicate.classScopes().bindings().isEmpty(), "two explicit owners cannot share canonical class layout");
                require(diagnostics.stream().filter(s -> s.contains("claimed by multiple classes")).count() == 2,
                    "both explicit conflicts diagnosed");
                GhidraClassBindings.remove(program, owner.getID(), TaskMonitor.DUMMY);
                var preferred = extract(program, symbols, target, 0, diagnostics);
                require(preferred.classScopes().bindings().size() == 1 && binding(preferred, otherOwner.getID()).source() == BindingSource.EXPLICIT_SAVED,
                    "one explicit owner precedes competing automatic inference");
                GhidraClassBindings.save(program, otherOwner, distinct, "separate static-only layout", TaskMonitor.DUMMY);
                GhidraClassBindings.save(program, owner, layout, "explicit current object layout", TaskMonitor.DUMMY);
                var staticMethod = method(program, otherOwner, "static_method", 0x401100);
                var nested = table.createClass(owner, "Nested", SourceType.USER_DEFINED);
                var nestedMethod = method(program, nested, "nested_method", 0x401200);
                var plain = method(program, null, "Counter::fake", 0x401300);
                symbols = List.of(new FunctionSymbol(method.getName(true), 0x401000, 4),
                    new FunctionSymbol(staticMethod.getName(true), 0x401100, 4),
                    new FunctionSymbol(nestedMethod.getName(true), 0x401200, 4),
                    new FunctionSymbol(plain.getName(), 0x401300, 4));
                var library = program.getExternalManager().addExternalLibraryName("fixture_library", SourceType.USER_DEFINED);
                var externalOwner = table.createClass(library, "ExternalClass", SourceType.USER_DEFINED);
                var external = program.getExternalManager().addExtFunction(externalOwner, "declared", null, SourceType.USER_DEFINED).getFunction();
                external.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
                var full = extract(program, symbols, target, 0, diagnostics);
                require(full.classScopes().bindings().size() == 2 && !binding(full, owner.getID()).type().equals(binding(full, otherOwner.getID()).type()),
                    "distinct same-name layouts stay distinct");
                require(full.classScopes().methods().size() == 4 && full.classScopes().methods().stream().noneMatch(m -> m.id() == plain.getID()),
                    "literal qualified spelling does not invent class ownership");
                require(full.classScopes().scopes().stream().anyMatch(s -> s.id() == nested.getID() && s.parent() == owner.getID()),
                    "nested class retains real parent");
                var externalMethod = full.classScopes().methods().stream().filter(m -> m.id() == external.getID()).findFirst().orElseThrow();
                require(externalMethod.function().address() == -1 && externalMethod.function().declarationKey().equals("external:" + external.getID()),
                    "external method remains addressless with exact key");
                require(full.classScopes().scopes().stream().anyMatch(s -> s.id() == externalOwner.getID() && s.parent() == 0) &&
                    full.classScopes().scopes().stream().noneMatch(s -> s.id() == library.getID()), "library is not a source namespace");
                var selected = extract(program, List.of(symbols.getFirst()), target, 0, diagnostics);
                require(selected.classScopes().methods().size() == 2, "non-exported image functions do not acquire declarations");
                var reserved = new java.util.IdentityHashMap<ghidra.program.model.data.DataType,
                    ghidradwarfforge.types.TypeGraph.TypeRef>();
                reserved.put(layout, binding(full, owner.getID()).type());
                reserved.put(distinct, binding(full, otherOwner.getID()).type());
                var count = new CancelAt(Integer.MAX_VALUE);
                collect(program, method, full, reserved, count);
                for (int point = 1; point <= count.visits; point++) {
                    try {
                        collect(program, method, full, reserved, new CancelAt(point));
                        throw new AssertionError("collector cancellation ignored at " + point);
                    }
                    catch (CancelledException wanted) { checks++; }
                }
                require(original.equals(program.getOptions(GhidraClassBindings.OPTIONS_NAME)
                    .getString("class-" + owner.getID(), null)), "cancelled collection retains explicit record");
                expected = full.classScopes();
                program.setImageBase(program.getImageBase().add(0x200000), true);
                require(extract(program, symbols, target, 0x200000, diagnostics).classScopes().equals(expected),
                    "rebasing normalizes image references but preserves saved identities");
                var monitor = new TaskMonitorAdapter(true);
                monitor.cancel();
                try {
                    GhidraTypeGraph.extract(program, symbols, target, 0x200000, monitor, diagnostics::add);
                    throw new AssertionError("cancel ignored");
                }
                catch (CancelledException wanted) { checks++; }
            }
            finally { program.endTransaction(tx, true); }
            program.getDBHandle().saveAs(saved.toFile(), false, TaskMonitor.DUMMY);
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(saved));
            var modified = Files.getLastModifiedTime(saved);
            var handle = new DBHandle(saved.toFile());
            var reopenedToken = new Object();
            ProgramDB reopened = null;
            try {
                reopened = new ProgramDB(handle, OpenMode.IMMUTABLE, TaskMonitor.DUMMY, reopenedToken);
                require(extract(reopened, symbols, target, 0x200000, diagnostics).classScopes().equals(expected),
                    "production extraction survives immutable reopen");
                require(extract(reopened, symbols, target, 0x200000, diagnostics).classScopes().equals(expected),
                    "deterministic repeated extraction");
            }
            finally {
                if (reopened != null) reopened.release(reopenedToken);
                else handle.close();
            }
            require(Arrays.equals(hash, MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(saved))) &&
                modified.equals(Files.getLastModifiedTime(saved)), "read-only extraction preserves database bytes and timestamp");
            System.out.println("class-scope-extraction-target=PASS " + languageId);
        }
        finally {
            program.release(token);
            Files.deleteIfExists(saved);
            Files.deleteIfExists(directory);
        }
    }

    private static final class CancelAt extends TaskMonitorAdapter {
        private final int limit;
        private int visits;
        CancelAt(int limit) { super(true); this.limit = limit; }
        @Override public void checkCancelled() throws CancelledException {
            if (++visits == limit) throw new CancelledException();
        }
    }

    private static void collect(Program program, Function method, ProgramTypeModel full,
            java.util.Map<ghidra.program.model.data.DataType, ghidradwarfforge.types.TypeGraph.TypeRef> reserved,
            TaskMonitor monitor) throws CancelledException {
        var collector = new GhidraClassScopes(program, monitor, ignored -> { });
        var signature = full.functions().stream().filter(f -> f.address() == 0x401000).findFirst().orElseThrow();
        collector.record(method, ClassScopeModel.FunctionReference.definition(signature.name(), signature.address()), signature.parameters());
        collector.prepare(type -> java.util.Objects.requireNonNull(reserved.get(type)));
        collector.finish(full.types());
    }

    private static Function method(Program program, GhidraClass owner, String name, long offset) throws Exception {
        var entry = program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
        program.getMemory().createInitializedBlock("body_" + offset, entry, 4, (byte) 0, TaskMonitor.DUMMY, false);
        var function = program.getFunctionManager().createFunction(name, entry, new AddressSet(entry, entry.add(3)), SourceType.USER_DEFINED);
        if (owner != null) function.setParentNamespace(owner);
        function.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
        return function;
    }

    private static ProgramTypeModel extract(Program program, List<FunctionSymbol> symbols, String target,
            long delta, List<String> diagnostics) throws Exception {
        diagnostics.clear();
        return GhidraTypeGraph.extract(program, symbols, target, delta, TaskMonitor.DUMMY, diagnostics::add);
    }

    private static ClassScopeModel.Binding binding(ProgramTypeModel model, long classId) {
        return model.classScopes().bindings().stream().filter(b -> b.classId() == classId).findFirst().orElseThrow();
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
