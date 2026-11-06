// Observe retained demangled names after explicit analyst renaming.
// @category DWARF.Tests
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.database.symbol.EquateManager;
import ghidradwarfforge.GhidraEquateNames;
import ghidradwarfforge.GhidraFunctionSymbols;
import ghidradwarfforge.GhidraAnnotationInventory;
import ghidradwarfforge.GhidraEquateEvidence;
import ghidradwarfforge.annotations.EquateCatalog;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.elf.EquateNameReservations;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.TypeGraph;
import com.google.gson.GsonBuilder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public class VerifyRetainedEquateNames extends GhidraScript {
    @Override public void run() throws Exception {
        var renames = Map.of("retained_lookup", "curated_retained_function",
            "forge_equate_type_u64", "curated_type_named_function");
        if (getScriptArgs()[0].equals("setup")) {
            for (var functions = currentProgram.getFunctionManager().getFunctions(true); functions.hasNext();) {
                var function = functions.next();
                String renamed = renames.get(function.getName());
                if (renamed != null) function.setName(renamed, SourceType.USER_DEFINED);
            }
            var proposed = new EnumDataType("RetainedEquateDisplays", 8);
            proposed.add("retained_lookup", 17);
            proposed.add("forge_equate_type_u64", 18);
            proposed.add("VISIBLE_EQUATE", 19);
            var saved = currentProgram.getDataTypeManager().addDataType(proposed, DataTypeConflictHandler.DEFAULT_HANDLER);
            for (long value : new long[] {17, 18, 19}) {
                currentProgram.getEquateTable().createEquate(EquateManager.formatNameForEquate(saved.getUniversalID(), value), value);
            }
        }
        var functions = GhidraFunctionSymbols.extract(currentProgram, monitor, ignored -> { }, 0);
        if (!functions.stream().map(f -> f.name()).toList().containsAll(renames.values())) {
            throw new AssertionError("curated function names missing");
        }
        var names = EquateNameReservations.read(ElfImage.read(Path.of(currentProgram.getExecutablePath())),
            new ProgramTypeModel(new TypeGraph(List.of()), List.of(), List.of()), functions, List.of(),
            monitor::isCancelled, ignored -> { });
        for (String name : renames.keySet()) if (names.test(name)) throw new AssertionError("fixture masks retained-name gap: " + name);
        var complete = GhidraEquateNames.extend(currentProgram, names, monitor);
        for (String name : renames.keySet()) if (!complete.test(name)) throw new AssertionError("demangled spelling not reserved: " + name);
        var inventory = GhidraAnnotationInventory.read(currentProgram, new GhidraAnnotationInventory.Limits(10000, 1000000), monitor);
        var evidence = GhidraEquateEvidence.interpret(currentProgram, inventory, Map.of(), monitor);
        var catalog = EquateCatalog.plan(evidence, complete, complete.size(), monitor::isCancelled);
        int conflicts = 0;
        for (var entry : catalog.entries()) {
            String display = EquateCatalog.display(entry.evidence());
            if (renames.containsKey(display)) {
                if (!entry.directReason().equals("REAL_NAME_CONFLICT") || entry.constants().stream().anyMatch(c -> c.direct())) {
                    throw new AssertionError("retained function shadowed by equate " + display);
                }
                conflicts++;
            }
        }
        if (conflicts != 2) throw new AssertionError("retained-name conflict controls missing");
        var result = new TreeMap<String, Object>();
        result.put("constants", catalog.entries().stream().map(entry -> new TreeMap<>(Map.of("storedName", entry.evidence().stored().storedName(),
            "constants", entry.constants(), "directReason", entry.directReason()))).toList());
        result.put("renamedFunctions", functions.stream().filter(f -> renames.containsValue(f.name())).toList());
        result.put("reservedNames", complete.namedReservations().stream().sorted().toList());
        Files.writeString(Path.of(getScriptArgs()[1]), new GsonBuilder().setPrettyPrinting().create().toJson(result) + "\n");
        println("retained-equate-names=PASS");
    }
}
