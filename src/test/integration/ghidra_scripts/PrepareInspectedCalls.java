// Saves compiler-correlated callee signatures and records their actual physical graphs.
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
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.GhidraImageBase;

public class PrepareInspectedCalls extends GhidraScript {
    @Override
    protected void run() throws Exception {
        var args = getScriptArgs();
        if (args.length != 2 && args.length != 3) throw new IllegalArgumentException("symbol-table output-json [observe]");
        boolean observe = args.length == 3 && args[2].equals("observe");
        if (args.length == 3 && !observe) throw new IllegalArgumentException("expected observe");
        long delta = currentProgram.getImageBase().getOffset() - GhidraImageBase.originalImageBase(currentProgram);
        var type = new IntegerDataType(currentProgram.getDataTypeManager());
        var convention = currentProgram.getCompilerSpec().getDefaultCallingConvention();
        if (convention == null || convention.isErrorPlaceholder()) throw new AssertionError("unresolved ABI");
        var records = new LinkedHashMap<String, Object>();
        for (String line : Files.readAllLines(Path.of(args[0]))) {
            monitor.checkCancelled();
            String[] fields = line.trim().split("\\s+");
            if (fields.length != 8 || !fields[7].startsWith("inspected_")) continue;
            String name = fields[7];
            var entry = toAddr(Long.parseUnsignedLong(fields[1], 16) + delta);
            if (fields[3].equals("OBJECT")) {
                if (!observe) {
                    DataUtilities.createData(currentProgram, entry, type, type.getLength(),
                        DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
                    currentProgram.getSymbolTable().createLabel(entry, name, SourceType.USER_DEFINED).setPrimary();
                }
                if (!getDataAt(entry).getDataType().isEquivalent(type) ||
                        !currentProgram.getSymbolTable().getPrimarySymbol(entry).getName().equals(name)) throw new AssertionError(name);
                records.put(name, entry.getOffset() - delta);
                continue;
            }
            if (!fields[3].equals("FUNC")) continue;
            Function function = getFunctionAt(entry);
            if (function == null || !function.getBody().getMaxAddress().next().equals(entry.add(Long.parseLong(fields[2])))) {
                throw new AssertionError("callee extent " + name);
            }
            if (!observe) {
                function.setName(name, SourceType.USER_DEFINED);
                function.setCallingConvention(convention.getName());
                function.setReturnType(type, SourceType.USER_DEFINED);
                function.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true,
                    SourceType.USER_DEFINED, new ParameterImpl("value", type, currentProgram, SourceType.USER_DEFINED));
            }
            if (!function.getName().equals(name) || function.getSignatureSource() != SourceType.USER_DEFINED ||
                    !function.getCallingConventionName().equals(convention.getName()) || function.getParameterCount() != 1 ||
                    !function.getParameter(0).getDataType().isEquivalent(type)) throw new AssertionError("signature " + name);
            var body = new ArrayList<Object>();
            for (var range : function.getBody()) body.add(List.of(range.getMinAddress().getOffset() - delta,
                range.getMaxAddress().getOffset() - delta + 1));
            var instructions = new ArrayList<Object>();
            for (var instruction : currentProgram.getListing().getInstructions(function.getBody(), true)) {
                monitor.checkCancelled();
                instructions.add(Map.of("address", instruction.getAddress().getOffset() - delta,
                    "next", instruction.getMaxAddress().getOffset() - delta + 1,
                    "bytes", java.util.HexFormat.of().formatHex(instruction.getBytes()),
                    "text", instruction.toString(), "flow", instruction.getFlowType().toString(),
                    "targets", java.util.Arrays.stream(instruction.getFlows()).map(address -> address.getOffset() - delta).toList(),
                    "pcode", java.util.Arrays.stream(instruction.getPcode()).map(Object::toString).toList()));
            }
            records.put(name, Map.of("entry", entry.getOffset() - delta, "body", body, "instructions", instructions,
                "convention", function.getCallingConventionName(), "symbolId", function.getSymbol().getID(),
                "unaffected", java.util.Arrays.stream(convention.getUnaffectedList()).map(Object::toString).toList()));
        }
        if (records.size() != 9) throw new AssertionError("expected seven callees and two globals: " + records.keySet());
        Files.writeString(Path.of(args[1]), new GsonBuilder().setPrettyPrinting().create().toJson(records) + "\n");
        println("inspected-calls-origin=" + GhidraImageBase.class.getProtectionDomain().getCodeSource().getLocation());
        println("inspected-calls-java=" + System.getProperty("java.version"));
        println("inspected-calls-preparation=PASS");
    }
}
