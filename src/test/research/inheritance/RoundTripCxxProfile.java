// Exercise the public analyst script against the independently curated fixture.
// @category DWARF.Tests

import com.google.gson.Gson;
import com.google.gson.JsonParser;
import ghidra.app.script.GhidraScript;
import ghidradwarfforge.*;
import ghidradwarfforge.output.CxxSelection;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

public class RoundTripCxxProfile extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) throw new IllegalArgumentException("capture-clear|assert-clear|assert-saved selection.json");
        Path selection = Path.of(args[1]);
        Path expected = Path.of(args[1] + ".expected.json");
        var json = new Gson();
        switch (args[0]) {
            case "capture-clear" -> {
                if (Files.exists(selection) || Files.exists(expected)) throw new IllegalArgumentException("fixture outputs already exist");
                var records = records();
                if (records.isEmpty()) throw new AssertionError("fixture bindings are absent");
                Files.writeString(expected, json.toJson(records));
                var inventory = GhidraCxxProfile.inspect(currentProgram, "", monitor);
                if (!((List<?>) inventory.get("diagnostics")).isEmpty()) throw new AssertionError(inventory.get("diagnostics"));
                Files.writeString(selection, json.toJson(inventory.get("selection")));
                var selected = CxxSelection.read(selection, monitor::isCancelled);
                if (selected.classes().size() != 11 || selected.declarations().size() != 1 ||
                        selected.inheritance().virtualMethods().size() != 15 || selected.vtables().size() != 7) {
                    throw new AssertionError("configuration roundtrip would be vacuous or incomplete");
                }
                for (var table : selected.vtables()) GhidraVtableBindings.remove(currentProgram, table.symbolId(), monitor);
                for (var declaration : selected.declarations()) GhidraDeclarationBindings.remove(currentProgram, declaration.methodId(), monitor);
                for (var owner : selected.classes()) GhidraClassBindings.remove(currentProgram, owner.classId(), monitor);
                GhidraInheritanceBindings.remove(currentProgram, monitor);
                if (!records().isEmpty()) throw new AssertionError("fixture metadata was not cleared");
            }
            case "assert-clear" -> {
                if (!records().isEmpty()) throw new AssertionError("preview persisted configuration");
            }
            case "assert-saved" -> {
                var actual = json.toJsonTree(records());
                if (!actual.equals(JsonParser.parseString(Files.readString(expected)))) {
                    throw new AssertionError("configuration differs from independently curated evidence");
                }
            }
            default -> throw new IllegalArgumentException("unknown fixture action");
        }
        println("cxx-profile-roundtrip=" + args[0] + " PASS");
    }

    private Map<String, String> records() throws Exception {
        var result = new TreeMap<String, String>();
        for (String group : List.of(GhidraClassBindings.OPTIONS_NAME, GhidraDeclarationBindings.OPTIONS_NAME,
                GhidraInheritanceBindings.OPTIONS_NAME, GhidraVtableBindings.OPTIONS_NAME)) {
            monitor.checkCancelled();
            if (!currentProgram.getOptionsNames().contains(group)) continue;
            var options = currentProgram.getOptions(group);
            for (String key : options.getOptionNames()) result.put(group + "/" + key, options.getString(key, null));
        }
        return result;
    }
}
