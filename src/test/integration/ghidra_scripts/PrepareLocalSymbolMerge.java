// @category DWARF.Tests
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Map;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.GhidraImageBase;

public class PrepareLocalSymbolMerge extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2 || !java.util.List.of("curate", "observe").contains(args[0])) {
            throw new IllegalArgumentException("<curate|observe> <output.json>");
        }
        var records = new ArrayList<Object>();
        long delta = currentProgram.getImageBase().getOffset() - GhidraImageBase.originalImageBase(currentProgram);
        var functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            monitor.checkCancelled();
            var function = functions.next();
            if (!function.getName().startsWith("analyst_")) continue;
            String name = function.getName().replace("analyst_", "alternate_");
            var table = currentProgram.getSymbolTable();
            var alias = args[0].equals("curate") ? table.createLabel(function.getEntryPoint(), name,
                function.getParentNamespace(), SourceType.USER_DEFINED) :
                table.getSymbol(name, function.getEntryPoint(), function.getParentNamespace());
            if (alias == null || function.getBody().getNumAddressRanges() != 1 ||
                    !function.getBody().getMinAddress().equals(function.getEntryPoint())) {
                throw new AssertionError("missing alias or unexpected body");
            }
            if (alias.isPrimary() || alias.getSource() != SourceType.USER_DEFINED ||
                    !alias.getAddress().equals(function.getEntryPoint())) throw new AssertionError("invalid alias");
            records.add(Map.of("primary", function.getName(true), "alias", alias.getName(true),
                "entry", alias.getAddress().getOffset() - delta, "size", function.getBody().getNumAddresses(),
                "source", alias.getSource().name(),
                "kind", alias.getSymbolType().toString(), "isPrimary", alias.isPrimary()));
        }
        if (records.size() != 2) throw new AssertionError("expected two aliases");
        Files.writeString(Path.of(args[1]), new GsonBuilder().setPrettyPrinting().create().toJson(records) + "\n");
    }
}
