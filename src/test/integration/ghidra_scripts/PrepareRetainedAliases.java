// Curate typed functions and owned statics using independent compiler addresses.
// @category DWARF.Tests
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.GhidraFunctionSymbols;
import ghidradwarfforge.GhidraImageBase;

public class PrepareRetainedAliases extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3 || !List.of("curate", "observe").contains(args[0])) {
            throw new IllegalArgumentException("<curate|observe> <address-records> <output.json>");
        }
        long delta = currentProgram.getImageBase().getOffset() - GhidraImageBase.originalImageBase(currentProgram);
        var rows = new ArrayList<Object>();
        for (String line : Files.readAllLines(Path.of(args[1]))) {
            monitor.checkCancelled();
            String[] fields = line.split(" ");
            if (fields.length != 4) throw new IllegalArgumentException("invalid address record");
            var entry = toAddr(Math.addExact(Long.decode(fields[1]), delta));
            var end = toAddr(Math.addExact(Long.decode(fields[2]), delta));
            var memory = toAddr(Math.addExact(Long.decode(fields[3]), delta));
            Function function = getFunctionAt(entry);
            if (function == null || function.getBody().getNumAddressRanges() != 1 ||
                    !function.getBody().getMinAddress().equals(entry) ||
                    !function.getBody().getMaxAddress().add(1).equals(end)) {
                throw new AssertionError("compiler/Ghidra body disagreement for " + fields[0]);
            }
            var integer = IntegerDataType.dataType;
            if (args[0].equals("curate")) {
                var owner = currentProgram.getSymbolTable().getOrCreateNameSpace(
                    currentProgram.getGlobalNamespace(), "recovered", SourceType.USER_DEFINED);
                function.setParentNamespace(owner);
                function.setName(fields[0], SourceType.USER_DEFINED);
                function.updateFunction(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName(),
                    new ReturnParameterImpl(integer, currentProgram),
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED,
                    new ParameterImpl("value", integer, currentProgram));
                DataUtilities.createData(currentProgram, memory, integer, 4,
                    DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
                currentProgram.getSymbolTable().createLabel(memory, "private_count", function,
                    SourceType.USER_DEFINED).setPrimary();
                // This imported-source label is deliberately absent from the ELF.
                // Its provenance flag must not turn it into an original alias.
                currentProgram.getSymbolTable().createLabel(entry, "unbacked_" + fields[0], SourceType.IMPORTED);
            }
            var data = currentProgram.getSymbolTable().getPrimarySymbol(memory);
            if (!function.getName(true).equals("recovered::" + fields[0]) ||
                    function.getSymbol().getSource() != SourceType.USER_DEFINED ||
                    function.getSignatureSource() != SourceType.USER_DEFINED ||
                    function.getParameterCount() != 1 || !function.getParameter(0).getName().equals("value") ||
                    function.getParameter(0).getLength() != 4 || function.getReturnType().getLength() != 4 ||
                    data == null || !data.getName().equals("private_count") ||
                    !data.getParentNamespace().equals(function)) {
                throw new AssertionError("curated identity or owned data did not persist");
            }
            var labels = new ArrayList<Object>();
            for (var symbol : currentProgram.getSymbolTable().getSymbols(entry)) {
                labels.add(Map.of("name", symbol.getName(true), "source", symbol.getSource().name(),
                    "primary", symbol.isPrimary(), "kind", symbol.getSymbolType().toString()));
            }
            rows.add(Map.of("name", function.getName(true), "entry", entry.getOffset() - delta,
                "end", end.getOffset() - delta, "privateAddress", memory.getOffset() - delta,
                "signature", function.getSignature().getPrototypeString(), "labels", labels));
        }
        if (rows.size() != 2) throw new AssertionError("expected two distinct function bodies");
        var result = new LinkedHashMap<String, Object>();
        result.put("functions", rows);
        result.put("rebaseDelta", delta);
        result.put("java", System.getProperty("java.version"));
        result.put("origin", GhidraFunctionSymbols.class.getProtectionDomain().getCodeSource().getLocation().toString());
        Files.writeString(Path.of(args[2]), new GsonBuilder().setPrettyPrinting().create().toJson(result) + "\n");
    }
}
