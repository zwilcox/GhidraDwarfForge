package ghidradwarfforge;

import java.util.*;

import ghidra.framework.options.OptionType;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.output.CxxSelection;
import ghidradwarfforge.targets.CxxAbiProfile;
import ghidradwarfforge.types.InheritanceModel;

/** Saved identities, rejected updates and inventory limits against real ProgramDB state. */
public final class CxxProfileBoundarySmoke {
    private static final TaskMonitor MONITOR = TaskMonitor.DUMMY;
    private static final CxxSelection.Removals NONE = new CxxSelection.Removals(List.of(), List.of(), List.of());
    private static final List<String> GROUPS = List.of(GhidraClassBindings.OPTIONS_NAME,
        GhidraDeclarationBindings.OPTIONS_NAME, GhidraVtableBindings.OPTIONS_NAME,
        GhidraInheritanceBindings.OPTIONS_NAME, "Analyst");
    private static int checks;

    private CxxProfileBoundarySmoke() { }

    public static void check() throws Exception {
        identities("x86:LE:64:default", CxxAbiProfile.ITANIUM_X86_64);
        identities("AARCH64:LE:64:v8A", CxxAbiProfile.ITANIUM_AARCH64);
        inventory();
        System.out.println("cxx-profile-boundaries=PASS checks=" + checks);
    }

    private static void identities(String languageId, CxxAbiProfile abi) throws Exception {
        Object consumer = new Object();
        var program = create(languageId, consumer);
        try {
            long[] ids = new long[6];
            edit(program, () -> {
                var symbols = program.getSymbolTable();
                ids[0] = symbols.createClass(program.getGlobalNamespace(), "First", SourceType.USER_DEFINED).getID();
                ids[1] = symbols.createClass(program.getGlobalNamespace(), "Second", SourceType.USER_DEFINED).getID();
                var manager = program.getDataTypeManager();
                ids[2] = manager.getID(manager.addDataType(new StructureDataType("First", 16), DataTypeConflictHandler.DEFAULT_HANDLER));
                ids[3] = manager.getID(manager.addDataType(new StructureDataType("Second", 16), DataTypeConflictHandler.DEFAULT_HANDLER));
                ids[4] = symbols.createLabel(program.getMinAddress(), "analyst_label", SourceType.USER_DEFINED).getID();
                ids[5] = manager.getID(manager.addDataType(new ArrayDataType(ByteDataType.dataType, 8, 1), DataTypeConflictHandler.DEFAULT_HANDLER));
            });
            var first = new CxxSelection.ClassBinding(ids[0], ids[2], "original first evidence");
            var second = new CxxSelection.ClassBinding(ids[1], ids[3], "original second evidence");
            GhidraCxxProfile.configure(program, selection(program, abi, List.of(first, second), NONE), true, MONITOR);
            var original = records(program);
            byte[] memory = memory(program);
            for (long[] wrong : List.of(new long[] {Long.MAX_VALUE, ids[2]}, new long[] {ids[4], ids[2]},
                    new long[] {ids[0], Long.MAX_VALUE}, new long[] {ids[0], ids[5]})) {
                var bad = new CxxSelection.ClassBinding(wrong[0], wrong[1], "rejected identity");
                rejects(() -> GhidraCxxProfile.configure(program, selection(program, abi, List.of(bad), NONE), true, MONITOR),
                    "selected class or structure identity is absent");
                require(records(program).equals(original), "absent/wrong identity preserves records");
            }
            // Only one selected row: conflict is with a retained canonical type, not parser duplication.
            var duplicate = new CxxSelection.ClassBinding(ids[1], ids[2], "must roll back overwritten second binding");
            rejects(() -> GhidraCxxProfile.configure(program, selection(program, abi, List.of(duplicate), NONE), true, MONITOR),
                "retained class binding is stale or shares a canonical type");
            require(records(program).equals(original), "retained canonical collision restores overwritten record");
            var changed = new CxxSelection.ClassBinding(ids[0], ids[2], "new evidence written before late rejection");
            for (String group : GROUPS.subList(1, 3)) {
                boolean declaration = group.equals(GhidraDeclarationBindings.OPTIONS_NAME);
                String key = (declaration ? "method-" : "symbol-") + "999999";
                edit(program, () -> program.getOptions(group).setString(key, "invalid saved analyst record"));
                var stale = records(program);
                rejects(() -> GhidraCxxProfile.configure(program, selection(program, abi, List.of(changed), NONE), true, MONITOR),
                    declaration ? "retained declaration binding is stale" : "retained vtable binding is stale");
                require(records(program).equals(stale), "late retained rejection restores earlier selected evidence");
                var inspected = GhidraCxxProfile.inspect(program, "no candidates match this filter", MONITOR);
                var template = (Map<?, ?>) inspected.get("selection");
                require(((List<?>) template.get(declaration ? "declarations" : "vtables")).isEmpty(), "invalid saved row not offered as valid selection");
                require(!((List<?>) inspected.get("diagnostics")).isEmpty(), "invalid saved row diagnosed");
                require(records(program).equals(stale), "inventory never repairs stale saved data");
                var removal = new CxxSelection.Removals(List.of(), declaration ? List.of(999999L) : List.of(), declaration ? List.of() : List.of(999999L));
                GhidraCxxProfile.configure(program, selection(program, abi, List.of(), removal), false, MONITOR);
                require(records(program).equals(stale), "preview restores explicit removal");
                GhidraCxxProfile.configure(program, selection(program, abi, List.of(), removal), true, MONITOR);
                require(records(program).equals(original), "explicit removal alone restores valid saved configuration");
            }
            require(Arrays.equals(memory, memory(program)), "rejected configurations preserve target bytes");
            require(program.getSymbolTable().getSymbol(ids[4]).getName().equals("analyst_label"), "analyst label preserved");
        }
        finally { program.release(consumer); }
    }

    private static void inventory() throws Exception {
        Object consumer = new Object();
        var program = create("x86:LE:64:default", consumer);
        try {
            rejects(() -> GhidraCxxProfile.inspect(program, null, MONITOR), "inventory filter exceeds bound");
            rejects(() -> GhidraCxxProfile.inspect(program, "x".repeat(1025), MONITOR), "inventory filter exceeds bound");
            require(!(boolean) GhidraCxxProfile.inspect(program, "x".repeat(1024), MONITOR).get("candidates_truncated"), "maximum filter accepted");
            for (int end : List.of(1024, 1025)) {
                edit(program, () -> {
                    for (int i = end == 1024 ? 0 : 1024; i < end; i++) {
                        var symbols = program.getSymbolTable();
                        symbols.createClass(program.getGlobalNamespace(), "owner_" + i, SourceType.USER_DEFINED);
                        program.getDataTypeManager().addDataType(new StructureDataType("layout_" + i, 4), DataTypeConflictHandler.DEFAULT_HANDLER);
                        var address = program.getMinAddress().add(i * 2L);
                        symbols.createLabel(address, "label_" + i, SourceType.USER_DEFINED);
                        program.getFunctionManager().createFunction("method_" + i, address.add(1), new AddressSet(address.add(1)), SourceType.USER_DEFINED);
                    }
                });
                long modification = program.getModificationNumber();
                for (var entry : Map.of("owner_", "classes", "layout_", "structures", "label_", "labels", "method_", "methods").entrySet()) {
                    var result = GhidraCxxProfile.inspect(program, entry.getKey(), MONITOR);
                    var candidates = (List<?>) result.get(entry.getValue());
                    require(candidates.size() == 1024, "candidate cap: " + entry);
                    var unique = new HashSet<Object>();
                    for (Object candidate : candidates) {
                        var row = (Map<?, ?>) candidate;
                        require(unique.add(row.get("id")), "candidate identity appears only once");
                        require(row.get(entry.getValue().equals("structures") ? "path" : "name").toString().contains(entry.getKey()),
                            "candidate filter respected");
                    }
                    require(result.get("candidates_truncated").equals(end > 1024), "exact boundary truncation: " + entry);
                    require(result.equals(GhidraCxxProfile.inspect(program, entry.getKey(), MONITOR)), "repeat inventory deterministic");
                }
                require(program.getModificationNumber() == modification, "bounded inventory never changes program");
            }
            // Non-memory external labels are excluded; namespace symbols are not candidate methods.
            edit(program, () -> program.getExternalManager().addExtLocation("external_library", "external_label", null, SourceType.USER_DEFINED));
            var external = GhidraCxxProfile.inspect(program, "external_", MONITOR);
            require(((List<?>) external.get("labels")).isEmpty() && ((List<?>) external.get("methods")).isEmpty(), "non-memory and unrelated symbols excluded");
            String group = GhidraClassBindings.OPTIONS_NAME;
            for (String key : List.of("unexpected-1", "class-", "class-0", "class-01", "class--1", "class-12345678901234567890", "class-9223372036854775808")) {
                edit(program, () -> program.getOptions(group).setString(key, "saved invalid data"));
                var before = records(program);
                rejects(() -> GhidraCxxProfile.inspect(program, "no-match", MONITOR),
                    key.equals("class-9223372036854775808") ? "saved C++ record identity exceeds range" : "unexpected saved C++ record key");
                require(records(program).equals(before), "malformed identity read preserves data");
                edit(program, () -> program.getOptions(group).removeOption(key));
            }
            edit(program, () -> program.getOptions(group).setInt("class-1", 7));
            var typed = records(program);
            rejects(() -> GhidraCxxProfile.inspect(program, "no-match", MONITOR), "saved C++ record has incompatible option type");
            require(records(program).equals(typed), "incompatible option type not coerced");
            edit(program, () -> program.getOptions(group).removeOption("class-1"));
            edit(program, () -> {
                for (int i = 1; i <= 4096; i++) program.getOptions(group).setString("class-" + i, "invalid saved record");
            });
            var capped = GhidraCxxProfile.inspect(program, "no-match", MONITOR);
            require(((List<?>) ((Map<?, ?>) capped.get("selection")).get("classes")).isEmpty(), "4096 invalid records diagnosed without fabricated selection");
            require(((List<?>) capped.get("diagnostics")).size() == 4096, "each invalid saved class diagnosed");
            edit(program, () -> program.getOptions(group).setString("class-4097", "extra record"));
            var over = records(program);
            rejects(() -> GhidraCxxProfile.inspect(program, "no-match", MONITOR), "saved C++ record inventory exceeds bound");
            require(records(program).equals(over), "record count rejection preserves inventory");
            edit(program, () -> {
                for (int i = 1; i <= 4097; i++) program.getOptions(group).removeOption("class-" + i);
                program.getOptions(group).setString("class-1", "x".repeat(16 * 1024 * 1024));
            });
            var boundedText = GhidraCxxProfile.inspect(program, "no-match", MONITOR);
            require(((List<?>) boundedText.get("diagnostics")).size() == 1, "exact text budget accepted, malformed record diagnosed");
            edit(program, () -> program.getOptions(group).setString("class-2", "x"));
            var oversized = records(program);
            rejects(() -> GhidraCxxProfile.inspect(program, "no-match", MONITOR), "saved C++ record inventory exceeds 16 MiB text bound");
            require(records(program).equals(oversized), "text budget rejection preserves records");
            edit(program, () -> { program.getOptions(group).removeOption("class-1"); program.getOptions(group).removeOption("class-2"); });
            var beforeCancel = records(program);
            long modification = program.getModificationNumber();
            for (int stop : List.of(1, 500, 2000)) {
                var monitor = new TaskMonitorAdapter(true) {
                    private int calls;
                    @Override public void checkCancelled() throws CancelledException { if (++calls == stop) throw new CancelledException(); }
                };
                try { GhidraCxxProfile.inspect(program, "", monitor); throw new AssertionError("inventory ignored cancellation at " + stop); }
                catch (CancelledException expected) { checks++; }
                require(records(program).equals(beforeCancel), "cancelled inventory preserves metadata");
                require(program.getModificationNumber() == modification, "cancelled inventory never changes program");
            }
        }
        finally { program.release(consumer); }
    }

    private static ProgramDB create(String languageId, Object consumer) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(languageId));
        var program = new ProgramDB("Cxx boundaries", language, language.getDefaultCompilerSpec(), consumer);
        edit(program, () -> {
            var address = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x401000);
            program.getMemory().createInitializedBlock("analyst bytes", address, 4096, (byte) 0x42, MONITOR, false);
            program.getOptions("Analyst").setString("keep", "saved analyst evidence");
        });
        return program;
    }

    private static CxxSelection selection(Program program, CxxAbiProfile abi, List<CxxSelection.ClassBinding> classes, CxxSelection.Removals removals) {
        return new CxxSelection(program.getUniqueProgramID(), program.getLanguageID().toString(),
            program.getCompilerSpec().getCompilerSpecID().toString(), classes, List.of(),
            new InheritanceModel(abi, List.of(), List.of()), List.of(), removals);
    }

    private static Map<String, Object> records(Program program) {
        var result = new TreeMap<String, Object>();
        for (String group : GROUPS) {
            if (!program.getOptionsNames().contains(group)) continue;
            var options = program.getOptions(group);
            for (String key : options.getOptionNames()) {
                var type = options.getType(key);
                require(type == OptionType.STRING_TYPE || type == OptionType.INT_TYPE, "fixture contains expected option type");
                result.put(group + "/" + key, type == OptionType.STRING_TYPE ? options.getString(key, "") : options.getInt(key, 0));
            }
        }
        return result;
    }

    private static byte[] memory(Program program) throws Exception {
        byte[] bytes = new byte[4096];
        require(program.getMemory().getBytes(program.getMinAddress(), bytes) == bytes.length, "snapshot all target bytes");
        return bytes;
    }

    private interface Operation { void run() throws Exception; }
    private static void edit(Program program, Operation operation) throws Exception {
        int tx = program.startTransaction("analyst fixture edit");
        boolean commit = false;
        try { operation.run(); commit = true; }
        finally { program.endTransaction(tx, commit); }
    }
    private static void rejects(Operation operation, String message) throws Exception {
        try { operation.run(); throw new AssertionError("accepted invalid configuration: " + message); }
        catch (IllegalArgumentException expected) { require(expected.getMessage().startsWith(message), "rejection reason: " + expected); }
    }
    private static void require(boolean value, String message) { if (!value) throw new AssertionError(message); checks++; }
}
