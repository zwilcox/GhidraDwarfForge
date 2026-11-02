// @category DWARF.Tests
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;

public class PrepareArmHfaControls extends GhidraScript {
    protected void run() throws Exception {
        var args = getScriptArgs();
        if (args.length != 4 || !List.of("curate", "inspect").contains(args[0])) throw new IllegalArgumentException();
        String storage = args[3];
        if (!List.of("hfa", "base", "mixed").contains(storage)) throw new IllegalArgumentException();
        boolean core = !storage.equals("hfa");
        String convention = storage.equals("base") ? "__stdcall_softfp" : "__stdcall";
        var labels = new HashMap<String, Long>();
        for (String line : Files.readAllLines(Path.of(args[1]))) {
            var fields = line.split(" ");
            labels.put(fields[0], Long.decode(fields[1]));
        }
        var pair = new StructureDataType("FloatPair", 0, currentProgram.getDataTypeManager());
        pair.add(storage.equals("mixed") ? UnsignedIntegerDataType.dataType : FloatDataType.dataType, "first", null);
        pair.add(FloatDataType.dataType, "second", null);
        var function = getFunctionAt(toAddr(labels.get("hfa_control")));
        if (function == null) throw new AssertionError("missing assembly function");
        if (args[0].equals("curate")) {
            function.setName("hfa_control", SourceType.USER_DEFINED);
            function.updateFunction(convention, new ReturnParameterImpl(storage.equals("mixed") ? UnsignedIntegerDataType.dataType : FloatDataType.dataType, currentProgram),
                Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED,
                new ParameterImpl("value", pair, currentProgram, SourceType.USER_DEFINED),
                new ParameterImpl("destination", new PointerDataType(UnsignedIntegerDataType.dataType,
                    currentProgram.getDataTypeManager()), currentProgram, SourceType.USER_DEFINED),
                new ParameterImpl("replacement", UnsignedIntegerDataType.dataType, currentProgram, SourceType.USER_DEFINED));
            var input = toAddr(labels.get("control_input"));
            DataUtilities.createData(currentProgram, input, pair, pair.getLength(),
                DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
            createLabel(input, "control_input", true, SourceType.USER_DEFINED);
        }
        if (function.hasCustomVariableStorage() || !function.getCallingConventionName().equals(convention) ||
                function.getParameters().length != 3 ||
                !function.getParameter(0).getFormalDataType().isEquivalent(pair) ||
                !function.getParameter(1).getVariableStorage().toString().equals(core ? "r2:4" : "r0:4") ||
                !function.getParameter(2).getVariableStorage().toString().equals(core ? "r3:4" : "r1:4")) throw new AssertionError();
        Files.writeString(Path.of(args[2]), new GsonBuilder().setPrettyPrinting().create().toJson(Map.of(
            "signature", function.getPrototypeString(false, false),
            "storage", function.getParameter(0).getVariableStorage().toString(),
            "language", currentProgram.getLanguageID().toString(),
            "origin", ghidradwarfforge.GhidraVariableStorage.class.getProtectionDomain()
                .getCodeSource().getLocation().toString())) + "\n");
        println("hfa-control-preparation=PASS");
    }
}
