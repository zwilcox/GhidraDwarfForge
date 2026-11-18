package ghidradwarfforge;

import java.io.ByteArrayInputStream;
import java.util.*;

import ghidra.app.util.opinion.ElfLoader;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.GhidraVtableBindings.*;
import ghidradwarfforge.output.CxxSelection;
import ghidradwarfforge.targets.CxxAbiProfile;
import ghidradwarfforge.types.InheritanceModel;
import ghidradwarfforge.types.InheritanceModel.*;

/** Real file-backed ranges and saved identities; rejected updates must restore prior evidence. */
public final class CxxVtableConflictSmoke {
    private static final TaskMonitor MONITOR = TaskMonitor.DUMMY;
    private static final CxxSelection.Removals NONE = new CxxSelection.Removals(List.of(), List.of(), List.of());
    private static int checks;

    private CxxVtableConflictSmoke() { }

    public static void check() throws Exception {
        check("x86:LE:64:default", CxxAbiProfile.ITANIUM_X86_64);
        check("AARCH64:LE:64:v8A", CxxAbiProfile.ITANIUM_AARCH64);
        System.out.println("cxx-vtable-conflicts=PASS checks=" + checks);
    }

    private static void check(String languageId, CxxAbiProfile abi) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(languageId));
        Object consumer = new Object();
        var program = new ProgramDB("table conflicts", language, language.getDefaultCompilerSpec(), consumer);
        try {
            long[] classes = new long[2], types = new long[2], symbols = new long[7];
            int[] offsets = {32, 24, 40, 32, 8, 56, 80};
            byte[] originalBytes = new byte[128];
            Arrays.fill(originalBytes, 112, 128, (byte) 0x5a);
            int tx = program.startTransaction("analyst fixture");
            try {
                var space = program.getAddressFactory().getDefaultAddressSpace();
                program.setImageBase(space.getAddress(0x400000), true);
                program.setExecutableFormat(ElfLoader.ELF_NAME);
                program.getOptions(Program.PROGRAM_INFO).setString(ElfLoader.ELF_ORIGINAL_IMAGE_BASE_PROPERTY, "400000");
                var memory = program.getMemory();
                var file = memory.createFileBytes("fixture.elf", 0x1000, originalBytes.length,
                    new ByteArrayInputStream(originalBytes), MONITOR);
                memory.createInitializedBlock("tables", space.getAddress(0x402000), file, 0, originalBytes.length, false);
                for (int i = 0; i < classes.length; i++) {
                    String name = i == 0 ? "Child" : "Other";
                    var owner = program.getSymbolTable().createClass(program.getGlobalNamespace(), name, SourceType.USER_DEFINED);
                    var type = (Structure) program.getDataTypeManager().addDataType(new StructureDataType(name, 32), DataTypeConflictHandler.DEFAULT_HANDLER);
                    classes[i] = owner.getID(); types[i] = program.getDataTypeManager().getID(type);
                    GhidraClassBindings.save(program, owner, type, "saved " + name + " type", MONITOR);
                }
                for (int i = 0; i < symbols.length; i++) {
                    symbols[i] = program.getSymbolTable().createLabel(space.getAddress(0x402000 + offsets[i]),
                        "analyst_table_" + i, SourceType.USER_DEFINED).getID();
                }
                program.getOptions("Analyst").setString("keep", "independent saved evidence");
            }
            finally { program.endTransaction(tx, true); }
            var model = new InheritanceModel(abi, List.of(new Base(classes[0], classes[1], 0, Access.PUBLIC,
                new FixedBase(0, 16), "explicit base extent")), List.of());
            var base = request(symbols[0], classes[0], "_ZTV5Child", "Child");
            accepted(program, selection(program, model, List.of(), List.of(base), NONE), true);
            var baseline = records(program);
            var witness = GhidraVtableBindings.read(program, base.symbolId(), MONITOR, ignored -> { });
            require(witness.status() == Status.VALID && witness.snapshot().originalAddress() == 0x402020 &&
                witness.snapshot().fileOffset() == 0x1020, "baseline uses actual original address and FileBytes offset");
            var cases = List.of(
                request(symbols[1], classes[1], "_ZTV5Other", "Other"), // [24,48) overlaps [32,56).
                request(symbols[2], classes[1], "_ZTV5Other", "Other"), // [40,64) overlaps [32,56).
                request(symbols[3], classes[1], "_ZTV5Other", "Other"), // Same bytes, different saved label.
                request(symbols[6], classes[0], "_ZTV5Child", "Child"), // Disjoint ranges, same mangled identity.
                request(symbols[6], classes[1], "_ZTVN5ChildE", "Child")); // Distinct spelling, ambiguous lookup ownership.
            for (int i = 0; i < cases.size(); i++) {
                var candidate = cases.get(i);
                var changed = new CxxSelection.ClassBinding(classes[0], types[0], "new evidence must be rolled back");
                String classKey = GhidraClassBindings.OPTIONS_NAME + "/class-" + classes[0];
                boolean[] observedWrites = new boolean[1];
                var observer = new TaskMonitorAdapter(true) {
                    @Override public void checkCancelled() {
                        if (program.getOptions(GhidraVtableBindings.OPTIONS_NAME).contains("symbol-" + candidate.symbolId()) &&
                                !program.getOptions(GhidraClassBindings.OPTIONS_NAME).getString("class-" + classes[0], "").equals(baseline.get(classKey))) {
                            observedWrites[0] = true;
                        }
                    }
                };
                String expected = i == cases.size() - 1 ? "vtable lookup name denotes multiple classes" : "conflicting or overlapping selected vtable identities";
                try {
                    GhidraCxxProfile.configure(program, selection(program, model, List.of(changed), List.of(candidate), NONE), true, observer);
                    throw new AssertionError("accepted ambiguous table configuration: " + i);
                }
                catch (IllegalArgumentException failure) { require(failure.getMessage().equals(expected), "specific late conflict: " + failure); }
                require(observedWrites[0], "rejection occurs after both class and table writes");
                require(records(program).equals(baseline), "late rejection restores all previous saved records");
                require(GhidraVtableBindings.read(program, base.symbolId(), MONITOR, ignored -> { }).equals(witness), "retained table witness unchanged");
                require(Arrays.equals(memory(program), originalBytes), "rejection preserves memory and independent tail bytes");
            }
            // Touching boundaries are disjoint. Distinct manglings may resolve to the same class.
            for (var candidate : List.of(request(symbols[4], classes[1], "_ZTV5Other", "Other"),
                    request(symbols[5], classes[1], "_ZTV5Other", "Other"),
                    request(symbols[6], classes[1], "_ZTV5Other", "Other"),
                    request(symbols[6], classes[0], "_ZTVN5ChildE", "Child"))) {
                var selection = selection(program, model, List.of(), List.of(candidate), NONE);
                require(!accepted(program, selection, false).saved(), "valid table preview succeeds");
                require(records(program).equals(baseline), "valid preview restores original table configuration");
                require(accepted(program, selection, true).saved(), "nonconflicting table commits");
                var committed = records(program);
                var saved = GhidraVtableBindings.read(program, candidate.symbolId(), MONITOR, ignored -> { });
                require(saved.status() == Status.VALID && saved.snapshot().request().equals(candidate), "exact selected identity persisted");
                long modification = program.getModificationNumber();
                var inventory = GhidraCxxProfile.inspect(program, "no-matching-candidates", MONITOR);
                var template = (Map<?, ?>) inventory.get("selection");
                var tables = (List<?>) template.get("vtables");
                require(tables.size() == 2 && ((List<?>) inventory.get("diagnostics")).isEmpty(), "inventory retains both valid tables independent of candidate filter");
                var expectedIds = Set.of(Long.toString(base.symbolId()), Long.toString(candidate.symbolId()));
                var actualIds = new HashSet<Object>();
                for (Object row : tables) actualIds.add(((Map<?, ?>) row).get("symbol_id"));
                require(actualIds.equals(expectedIds), "inventory retains exact table identities");
                require(program.getModificationNumber() == modification && records(program).equals(committed), "inventory is read-only");
                accepted(program, selection, true);
                require(records(program).equals(committed), "repeated selection deterministic");
                var remove = new CxxSelection.Removals(List.of(), List.of(), List.of(candidate.symbolId()));
                accepted(program, selection(program, model, List.of(), List.of(), remove), true);
                require(records(program).equals(baseline), "removing additional table restores baseline exactly");
                require(Arrays.equals(memory(program), originalBytes), "successful metadata updates preserve target bytes");
            }
        }
        finally { program.release(consumer); }
    }

    private static Request request(long symbol, long owner, String mangled, String lookup) {
        return new Request(symbol, owner, mangled, lookup, 24, List.of(new AddressPoint(16, 0, "primary point")), "explicit table evidence");
    }

    private static GhidraCxxProfile.Result accepted(Program program, CxxSelection selection, boolean save) throws Exception {
        try { return GhidraCxxProfile.configure(program, selection, save, MONITOR); }
        catch (IllegalArgumentException failure) { throw new AssertionError("rejected valid disjoint table configuration", failure); }
    }

    private static CxxSelection selection(Program program, InheritanceModel model, List<CxxSelection.ClassBinding> classes,
            List<Request> tables, CxxSelection.Removals remove) {
        return new CxxSelection(program.getUniqueProgramID(), program.getLanguageID().toString(),
            program.getCompilerSpec().getCompilerSpecID().toString(), classes, List.of(), model, tables, remove);
    }

    private static Map<String, String> records(Program program) {
        var result = new TreeMap<String, String>();
        for (String group : List.of(GhidraClassBindings.OPTIONS_NAME, GhidraInheritanceBindings.OPTIONS_NAME,
                GhidraVtableBindings.OPTIONS_NAME, "Analyst")) {
            if (!program.getOptionsNames().contains(group)) continue;
            var options = program.getOptions(group);
            for (String key : options.getOptionNames()) result.put(group + "/" + key, options.getString(key, null));
        }
        return result;
    }

    private static byte[] memory(Program program) throws Exception {
        byte[] bytes = new byte[128];
        require(program.getMemory().getBytes(program.getMinAddress(), bytes) == bytes.length, "snapshot complete mapped bytes");
        return bytes;
    }
    private static void require(boolean value, String message) { if (!value) throw new AssertionError(message); checks++; }
}
