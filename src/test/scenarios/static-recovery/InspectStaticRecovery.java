// Inspect actual decompiler ownership and inferred types in a disposable read-only session.
// @category DWARF.Tests
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

import com.google.gson.GsonBuilder;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.GhidraStaticBindings;

public class InspectStaticRecovery extends GhidraScript {
    private Object inspect(HighSymbol symbol, String map) {
        var row = new LinkedHashMap<String, Object>();
        row.put("map", map);
        row.put("id", symbol.getId());
        row.put("name", symbol.getName());
        row.put("global", symbol.isGlobal());
        row.put("symbolType", symbol.getDataType().getPathName());
        row.put("symbolStorage", symbol.getStorage().toString());
        row.put("memoryStorage", symbol.getStorage().isMemoryStorage());
        row.put("namespaceId", symbol.getNamespace() == null ? null : symbol.getNamespace().getID());
        row.put("namespaceKind", symbol.getNamespace() == null ? null : symbol.getNamespace().getType().name());
        row.put("savedSymbol", symbol.getSymbol() == null ? null : symbol.getSymbol().getSymbolType().toString());
        row.put("savedName", symbol.getSymbol() == null ? null : symbol.getSymbol().getName());
        row.put("savedSource", symbol.getSymbol() == null ? null : symbol.getSymbol().getSource().name());
        row.put("wholeMapping", symbol.getFirstWholeMap() != null);
        var high = symbol.getHighVariable();
        if (high != null) {
            row.put("highKind", high.getClass().getSimpleName());
            row.put("highType", high.getDataType().getPathName());
            row.put("highSize", high.getSize());
            row.put("representative", high.getRepresentative().toString());
            row.put("offset", high.getOffset());
            row.put("instances", java.util.Arrays.stream(high.getInstances()).map(Object::toString).toList());
        }
        return row;
    }

    @Override
    protected void run() throws Exception {
        var args = getScriptArgs();
        if (args.length != 2) throw new IllegalArgumentException("mode output");
        String mode = args[0];
        var function = java.util.stream.StreamSupport.stream(currentProgram.getFunctionManager().getFunctions(true).spliterator(), false)
            .filter(f -> f.getName().equals("other_statics")).findFirst().orElseThrow();
        var matches = currentProgram.getSymbolTable().getSymbols("saved_other", function);
        if (matches.size() != 1) throw new AssertionError("missing or ambiguous function-owned label");
        var symbol = matches.getFirst();
        var address = symbol.getAddress();
        long savedId = symbol.getID();
        var bindingBefore = GhidraStaticBindings.read(currentProgram, savedId, monitor, this::println);
        if (!mode.equals("typed") && !mode.equals("stale")) {
            GhidraStaticBindings.remove(currentProgram, savedId, monitor);
        }
        if (!mode.equals("typed")) clearListing(address, address.add(3));
        if (mode.equals("namespace")) {
            var namespace = currentProgram.getSymbolTable().createNameSpace(currentProgram.getGlobalNamespace(),
                "other_statics", SourceType.IMPORTED);
            symbol.setNamespace(namespace);
        }
        else if (mode.equals("unowned") || mode.equals("local")) {
            symbol.delete();
            if (mode.equals("local")) {
                function.addLocalVariable(new LocalVariableImpl("inferred_static", 0, IntegerDataType.dataType,
                    address, currentProgram, SourceType.ANALYSIS), SourceType.ANALYSIS);
            }
        }
        else if (!List.of("typed", "undefined", "stale").contains(mode)) throw new IllegalArgumentException("unknown mode");
        var result = new LinkedHashMap<String, Object>();
        result.put("mode", mode);
        result.put("javaVersion", System.getProperty("java.version"));
        result.put("functionId", function.getID());
        result.put("originalSymbolId", savedId);
        result.put("bindingBefore", bindingBefore.status().name());
        result.put("bindingAfter", GhidraStaticBindings.read(currentProgram, savedId, monitor, this::println).status().name());
        result.put("objectAddress", address.toString());
        result.put("dataDefined", getDataAt(address) != null && getDataAt(address).isDefined());
        var rows = new ArrayList<Object>();
        var decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) throw new AssertionError("openProgram");
            var output = decompiler.decompileFunction(function, 30, monitor);
            if (!output.decompileCompleted() || output.getHighFunction() == null) throw new AssertionError(output.getErrorMessage());
            var high = output.getHighFunction();
            var globals = high.getGlobalSymbolMap().getSymbols();
            while (globals.hasNext()) rows.add(inspect(globals.next(), "global"));
            var locals = high.getLocalSymbolMap().getSymbols();
            while (locals.hasNext()) rows.add(inspect(locals.next(), "local"));
            result.put("syntheticC", output.getDecompiledFunction().getC());
        }
        finally { decompiler.dispose(); }
        result.put("symbols", rows);
        Files.writeString(Path.of(args[1]), new GsonBuilder().setPrettyPrinting().create().toJson(result) + "\n");
        println("static-recovery-probe=PASS");
    }
}
