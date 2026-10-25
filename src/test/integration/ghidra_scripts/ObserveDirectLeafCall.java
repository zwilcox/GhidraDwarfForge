// @category DWARF.Tests
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.GhidraTypeGraph;

public class ObserveDirectLeafCall extends GhidraScript {
    @Override
    protected void run() throws Exception {
        var rows = new ArrayList<Object>();
        for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
            if (!List.of("carry_across_call", "perturb").contains(function.getName())) {
                continue;
            }
            var row = new LinkedHashMap<String, Object>();
            row.put("name", function.getName());
            if (getScriptArgs()[0].equals("curate")) {
                function.updateFunction(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName(),
                    new ReturnParameterImpl(IntegerDataType.dataType, currentProgram),
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED,
                    new ParameterImpl("value", IntegerDataType.dataType, currentProgram));
            }
            row.put("convention", function.getCallingConventionName());
            row.put("signatureSource", function.getSignatureSource().name());
            row.put("customStorage", function.hasCustomVariableStorage());
            row.put("parameterStorage", function.getParameter(0).getVariableStorage().toString());
            row.put("entry", function.getEntryPoint().toString());
            row.put("end", function.getBody().getMaxAddress().add(1).toString());
            var unaffected = new ArrayList<String>();
            for (var node : function.getCallingConvention().getUnaffectedList()) {
                unaffected.add(node.toString() + " " + currentProgram.getRegister(node));
            }
            row.put("unaffected", unaffected);
            var instructions = new ArrayList<Object>();
            for (var instruction : currentProgram.getListing().getInstructions(function.getBody(), true)) {
                var item = new LinkedHashMap<String, Object>();
                item.put("address", instruction.getAddress().toString());
                item.put("next", instruction.getMaxAddress().next().toString());
                item.put("text", instruction.toString());
                item.put("flow", instruction.getFlowType().toString());
                item.put("fallThrough", String.valueOf(instruction.getFallThrough()));
                item.put("pcode", java.util.Arrays.stream(instruction.getPcode()).map(Object::toString).toList());
                instructions.add(item);
            }
            row.put("instructions", instructions);
            rows.add(row);
        }
        if (rows.size() != 2) { throw new AssertionError("missing fixture functions"); }
        var result = new LinkedHashMap<String, Object>();
        result.put("java", System.getProperty("java.version"));
        result.put("origin", GhidraTypeGraph.class.getProtectionDomain().getCodeSource().getLocation().toExternalForm());
        result.put("functions", rows);
        Files.writeString(Path.of(getScriptArgs()[1]), new GsonBuilder().setPrettyPrinting().create().toJson(result) + "\n");
    }
}
