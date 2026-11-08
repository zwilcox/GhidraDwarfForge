// @category DWARF.Tests
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.GhidraImageBase;
import ghidradwarfforge.nativeapi.DwarfTarget;
import java.nio.file.*;
import java.util.*;
import com.google.gson.GsonBuilder;

public class PrepareI386ExtendedReturn extends GhidraScript {
    protected void run() throws Exception {
        boolean curate = getScriptArgs()[0].equals("curate");
        long delta = currentProgram.getImageBase().getOffset() - GhidraImageBase.originalImageBase(currentProgram);
        var manager = currentProgram.getDataTypeManager();
        var types = Map.of("scalar_float", new FloatDataType(manager),
            "scalar_double", new DoubleDataType(manager), "scalar_extended", new LongDoubleDataType(manager),
            "source_helper", new LongDoubleDataType(manager));
        var extended = new LongDoubleDataType(manager);
        var alias = new TypedefDataType(CategoryPath.ROOT, "ExtendedAlias", extended, manager);
        var array = new ArrayDataType(alias, 3, alias.getLength(), manager);
        var record = new StructureDataType("ExtendedRecord", 0, manager);
        record.setPackingEnabled(true);
        record.add(new IntegerDataType(manager), "tag", null);
        record.add(alias, "value", null);
        record.add(new IntegerDataType(manager), "tail", null);
        boolean wide = currentProgram.getDefaultPointerSize() == 8;
        if (array.getLength() != (wide ? 48 : 36) || record.getLength() != (wide ? 48 : 20) ||
                record.getComponent(1).getOffset() != (wide ? 16 : 4) ||
                record.getComponent(2).getOffset() != (wide ? 32 : 16)) {
            throw new AssertionError("Unexpected compiler floating layout");
        }
        var globals = Map.of("extended_global", alias, "extended_array", array, "extended_record", record);
        var rows = new ArrayList<Object>();
        var dataRows = new ArrayList<Object>();
        for (String line : Files.readAllLines(Path.of(getScriptArgs()[1]))) {
            monitor.checkCancelled();
            var fields = line.split(" ");
            var address = toAddr(Long.decode(fields[1]) + delta);
            if (globals.containsKey(fields[0])) {
                if (curate) {
                    createLabel(address, fields[0], true, SourceType.USER_DEFINED);
                    DataUtilities.createData(currentProgram, address, globals.get(fields[0]), -1,
                        DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
                }
                var data = getDataAt(address);
                dataRows.add(Map.of("name", fields[0], "type", data.getDataType().getPathName(), "bytes", data.getLength()));
                continue;
            }
            var function = getFunctionAt(address);
            if (function == null) throw new AssertionError("Missing fixture function " + fields[0]);
            DataType type = types.get(fields[0]);
            if (type == null) throw new AssertionError("Unexpected fixture name");
            if (curate) {
                function.setName(fields[0], SourceType.USER_DEFINED);
                Parameter[] parameters = fields[0].equals("source_helper")
                    ? new Parameter[]{new ParameterImpl("value", type, currentProgram)}
                    : new Parameter[]{new ParameterImpl("a", type, currentProgram), new ParameterImpl("b", type, currentProgram)};
                function.updateFunction("__cdecl", new ReturnParameterImpl(type, currentProgram),
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED, parameters);
            }
            rows.add(Map.of("name", function.getName(), "return", function.getReturn().getVariableStorage().toString(),
                "parameters", Arrays.stream(function.getParameters()).map(p -> Map.of("name", p.getName(),
                    "storage", p.getVariableStorage().toString(), "type", p.getFormalDataType().getPathName())).toList()));
        }
        if (rows.size() != 4 || dataRows.size() != 3) throw new AssertionError("Incomplete fixture");
        Function caller = null;
        for (var candidate : currentProgram.getFunctionManager().getFunctions(true)) {
            if (candidate.getName().equals("scalar_extended")) caller = candidate;
        }
        if (caller == null) throw new AssertionError("Missing source-view caller");
        int calls = 0;
        for (var instruction : currentProgram.getListing().getInstructions(caller.getBody(), true)) {
            if (!instruction.getFlowType().isCall()) continue;
            calls++;
            if (curate) {
                var override = new FunctionDefinitionDataType("AnalystHelperSignature", manager);
                override.setReturnType(extended);
                override.setArguments(new ParameterDefinition[]{new ParameterDefinitionImpl("analyst_value", extended, null)});
                override.setCallingConvention("__cdecl");
                ghidra.program.model.pcode.HighFunctionDBUtil.writeOverride(caller, instruction.getAddress(), override);
            }
        }
        if (calls != 1) throw new AssertionError("Expected one actual helper call");
        var overrideRows = new ArrayList<Object>();
        var namespace = ghidra.program.model.pcode.HighFunction.findOverrideSpace(caller);
        if (namespace == null) throw new AssertionError("Missing analyst override namespace");
        var overrideSymbols = currentProgram.getSymbolTable().getSymbols(namespace);
        while (overrideSymbols.hasNext()) {
            var symbol = overrideSymbols.next();
            var override = ghidra.program.model.pcode.HighFunctionDBUtil.readOverride(symbol);
            if (override != null) overrideRows.add(Map.of("address", override.getAddress().toString(),
                "type", override.getDataType().getPathName(), "signature", override.getDataType().toString()));
        }
        if (overrideRows.size() != 1) throw new AssertionError("Missing saved analyst call signature");
        Files.writeString(Path.of(getScriptArgs()[2]), new GsonBuilder().setPrettyPrinting().create().toJson(
            Map.of("functions", rows, "globals", dataRows, "delta", delta, "overrides", overrideRows,
                "origin", DwarfTarget.class.getProtectionDomain().getCodeSource().getLocation().toString())));
    }
}
