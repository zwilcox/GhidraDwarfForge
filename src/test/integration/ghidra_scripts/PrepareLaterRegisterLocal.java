// @category DWARF.Tests
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.GhidraImageBase;
import ghidradwarfforge.GhidraTypeGraph;

public class PrepareLaterRegisterLocal extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if ((getScriptArgs().length != 2 && getScriptArgs().length != 3) ||
                !List.of("curate", "observe").contains(getScriptArgs()[0])) {
            throw new IllegalArgumentException("expected curate|observe output-json [read|definition]");
        }
        String firstUseKind = getScriptArgs().length == 3 ? getScriptArgs()[2] : "read";
        if (!List.of("read", "definition").contains(firstUseKind)) throw new IllegalArgumentException("invalid first use kind");
        var rows = new ArrayList<Object>();
        for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
            monitor.checkCancelled();
            if (!List.of("local32", "local64").contains(function.getName())) continue;
            var symbols = currentProgram.getSymbolTable().getGlobalSymbols(function.getName() + "_" + firstUseKind);
            if (symbols.size() != 1) throw new AssertionError("missing first-use label");
            var firstUseAddress = symbols.get(0).getAddress();
            if (getInstructionAt(firstUseAddress) == null || !function.getBody().contains(firstUseAddress)) {
                throw new AssertionError("first-use label is not an instruction");
            }
            boolean small = function.getName().equals("local32");
            boolean x86 = currentProgram.getLanguageID().toString().startsWith("x86:");
            var register = currentProgram.getRegister(x86 ? (small ? "R10D" : "R10") : (small ? "w9" : "x9"));
            var type = small ? IntegerDataType.dataType : LongLongDataType.dataType;
            int firstUse = Math.toIntExact(firstUseAddress.subtract(function.getEntryPoint()));
            if (firstUse <= 0) throw new AssertionError("expected later start");
            if (getScriptArgs()[0].equals("curate")) {
                function.updateFunction(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName(),
                    new ReturnParameterImpl(type, currentProgram), Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                    true, SourceType.USER_DEFINED, new ParameterImpl("input", type, currentProgram));
                for (var variable : function.getLocalVariables()) function.removeVariable(variable);
                function.addLocalVariable(new LocalVariableImpl("curated_held", firstUse, type,
                    register, currentProgram, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
            }
            var locals = function.getLocalVariables();
            if (locals.length != 1 || !locals[0].getName().equals("curated_held") ||
                    locals[0].getFirstUseOffset() != firstUse || locals[0].getSource() != SourceType.USER_DEFINED ||
                    locals[0].getRegister() != register || locals[0].getLength() != type.getLength()) {
                throw new AssertionError("curated storage did not persist");
            }
            var row = new LinkedHashMap<String, Object>();
            row.put("name", function.getName());
            row.put("entry", function.getEntryPoint().toString());
            row.put("end", function.getBody().getMaxAddress().add(1).toString());
            row.put("firstUse", firstUse);
            row.put("width", type.getLength());
            row.put("source", locals[0].getSource().name());
            row.put("storage", locals[0].getVariableStorage().toString());
            var instructions = new ArrayList<Object>();
            for (var instruction : currentProgram.getListing().getInstructions(function.getBody(), true)) {
                instructions.add(Map.of("address", instruction.getAddress().toString(),
                    "next", instruction.getMaxAddress().next().toString(), "text", instruction.toString(),
                    "bytes", java.util.HexFormat.of().formatHex(instruction.getBytes()),
                    "pcode", java.util.Arrays.stream(instruction.getPcode()).map(Object::toString).toList()));
            }
            row.put("instructions", instructions);
            rows.add(row);
        }
        if (rows.size() != 2) throw new AssertionError("missing fixture functions");
        var result = new LinkedHashMap<String, Object>();
        result.put("java", System.getProperty("java.version"));
        result.put("firstUseKind", firstUseKind);
        result.put("imageBase", currentProgram.getImageBase().getOffset());
        result.put("originalImageBase", GhidraImageBase.originalImageBase(currentProgram));
        result.put("origin", GhidraTypeGraph.class.getProtectionDomain().getCodeSource().getLocation().toExternalForm());
        result.put("functions", rows);
        Files.writeString(Path.of(getScriptArgs()[1]), new GsonBuilder().setPrettyPrinting().create().toJson(result) + "\n");
    }
}
