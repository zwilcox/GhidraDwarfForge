// @category DWARF.Tests
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;

import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;

/** Listing observations only; this script supplies no tail-call or argument proof. */
public class ObserveCallSiteEvidence extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (getScriptArgs().length != 1) throw new IllegalArgumentException("expected new output path");
        var rows = new ArrayList<Object>();
        for (var function : currentProgram.getFunctionManager().getFunctions(true)) {
            monitor.checkCancelled();
            if (!function.getName().startsWith("cs_")) continue;
            var row = new LinkedHashMap<String, Object>();
            row.put("name", function.getName());
            row.put("entry", function.getEntryPoint().toString());
            row.put("thunk", function.isThunk());
            var thunked = function.getThunkedFunction(false);
            row.put("thunkTarget", thunked == null ? null : thunked.getEntryPoint().toString());
            row.put("noReturn", function.hasNoReturn());
            row.put("callFixup", function.getCallFixup());
            row.put("convention", function.getCallingConventionName());
            var ranges = new ArrayList<Object>();
            for (var range : function.getBody().getAddressRanges(true)) {
                ranges.add(List.of(range.getMinAddress().toString(), range.getMaxAddress().toString()));
            }
            row.put("body", ranges);
            var instructions = new ArrayList<Object>();
            for (var instruction : currentProgram.getListing().getInstructions(function.getBody(), true)) {
                monitor.checkCancelled();
                var item = new LinkedHashMap<String, Object>();
                item.put("address", instruction.getAddress().toString());
                item.put("end", instruction.getMaxAddress().toString());
                item.put("bytes", HexFormat.of().formatHex(instruction.getParsedBytes()));
                item.put("text", instruction.toString());
                item.put("flow", instruction.getFlowType().toString());
                item.put("defaultFlow", instruction.getPrototype().getFlowType(instruction.getInstructionContext()).toString());
                item.put("override", instruction.getFlowOverride().name());
                item.put("fallThroughOverride", instruction.isFallThroughOverridden());
                item.put("lengthOverride", instruction.isLengthOverridden());
                item.put("fallThrough", String.valueOf(instruction.getFallThrough()));
                item.put("defaultFallThrough", String.valueOf(instruction.getDefaultFallThrough()));
                item.put("flows", Arrays.stream(instruction.getFlows()).map(Object::toString).toList());
                item.put("defaultFlows", Arrays.stream(instruction.getDefaultFlows()).map(Object::toString).toList());
                item.put("delayDepth", instruction.getDelaySlotDepth());
                item.put("inDelaySlot", instruction.isInDelaySlot());
                item.put("rawPcode", Arrays.stream(instruction.getPcode(false)).map(Object::toString).toList());
                item.put("effectivePcode", Arrays.stream(instruction.getPcode(true)).map(Object::toString).toList());
                item.put("references", Arrays.stream(instruction.getReferencesFrom()).map(Object::toString).toList());
                instructions.add(item);
            }
            row.put("instructions", instructions);
            rows.add(row);
        }
        if (rows.size() < 13) throw new AssertionError("missing fixture functions: " + rows.size());
        var result = new LinkedHashMap<String, Object>();
        result.put("scope", "Listing observations; no classified or accepted call sites");
        result.put("java", System.getProperty("java.version"));
        result.put("imageBase", currentProgram.getImageBase().toString());
        result.put("language", currentProgram.getLanguageID().getIdAsString());
        result.put("compiler", currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString());
        result.put("functions", rows);
        Files.writeString(Path.of(getScriptArgs()[0]), new GsonBuilder().setPrettyPrinting().create().toJson(result) + "\n",
            StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        println("call-site-observations=PASS functions=" + rows.size());
    }
}
