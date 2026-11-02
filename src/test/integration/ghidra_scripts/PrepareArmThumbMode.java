// Mixed ARM/Thumb fixture; require existing decoded functions, never alter mode.
// @category DWARF.Tests
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import com.google.gson.Gson;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;

public class PrepareArmThumbMode extends GhidraScript {
    private long imageBaseDelta;
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 6 && args.length != 7) {
            throw new IllegalArgumentException("thumb codeVA, arm codeVA, main codeVA, sink, pointer, arm-after codeVA");
        }
        var original = ghidradwarfforge.elf.ElfImage.read(
            java.nio.file.Path.of(currentProgram.getExecutablePath()));
        if (args.length == 7) {
            currentProgram.setImageBase(toAddr(Math.addExact(original.preferredImageBase(), Long.decode(args[6]))), true);
        }
        imageBaseDelta = currentProgram.getImageBase().getOffset() - original.preferredImageBase();
        DataType signedInt = new IntegerDataType(currentProgram.getDataTypeManager());
        var records = new ArrayList<Object>();
        records.add(prepare(args[0], "recovered_thumb_add", 1, signedInt, "left", "right"));
        records.add(prepare(args[1], "recovered_arm_call", 0, signedInt, "value"));
        records.add(prepare(args[2], "main", 0, signedInt));
        records.add(prepare(args[5], "recovered_arm_after", 0, signedInt, "value"));
        global(codeAddress(args[3]), "thumb_sink", signedInt);
        var signature = new FunctionDefinitionDataType("thumb_binary_op");
        signature.setReturnType(signedInt);
        signature.setArguments(new ParameterDefinitionImpl[] {
            new ParameterDefinitionImpl("left", signedInt, null),
            new ParameterDefinitionImpl("right", signedInt, null)
        });
        global(codeAddress(args[4]), "thumb_pointer", new PointerDataType(signature,
            currentProgram.getDataTypeManager()));
        var result = new LinkedHashMap<String, Object>();
        result.put("exporterClassOrigin", ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.class
            .getProtectionDomain().getCodeSource().getLocation().toExternalForm());
        result.put("language", currentProgram.getLanguageID().toString());
        result.put("compilerSpec", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        result.put("functions", records);
        result.put("imageBaseDelta", imageBaseDelta);
        println("ARM_THUMB_PREP=" + new Gson().toJson(result));
    }

    private Address codeAddress(String original) {
        return toAddr(Math.addExact(Long.decode(original), imageBaseDelta));
    }

    private Object prepare(String addressText, String name, int expectedMode,
            DataType type, String... parameterNames) throws Exception {
        monitor.checkCancelled();
        Address address = codeAddress(addressText);
        Function function = currentProgram.getFunctionManager().getFunctionAt(address);
        if (function == null) {
            throw new IllegalStateException("analysis did not create function at " + address);
        }
        var tmode = currentProgram.getRegister("TMode");
        BigInteger mode = currentProgram.getProgramContext().getValue(tmode, address, false);
        if (!BigInteger.valueOf(expectedMode).equals(mode)) {
            throw new IllegalStateException("unexpected TMode at " + address + ": " + mode);
        }
        var instructions = new ArrayList<Object>();
        var iterator = currentProgram.getListing().getInstructions(function.getBody(), true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            var instruction = iterator.next();
            var row = new LinkedHashMap<String, Object>();
            row.put("address", instruction.getAddress().toString());
            row.put("length", instruction.getLength());
            row.put("text", instruction.toString());
            row.put("tmode", currentProgram.getProgramContext().getValue(
                tmode, instruction.getAddress(), false));
            instructions.add(row);
        }
        if (instructions.isEmpty()) {
            throw new IllegalStateException("no decoded instructions at " + address);
        }
        function.setName(name, SourceType.USER_DEFINED);
        function.setCallingConvention(Function.DEFAULT_CALLING_CONVENTION_STRING);
        function.setReturnType(type, SourceType.USER_DEFINED);
        var parameters = new ArrayList<ParameterImpl>();
        for (String parameterName : parameterNames) {
            parameters.add(new ParameterImpl(parameterName, type, currentProgram, SourceType.USER_DEFINED));
        }
        function.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
            true, SourceType.USER_DEFINED, parameters.toArray(ParameterImpl[]::new));
        var result = new LinkedHashMap<String, Object>();
        result.put("entry", function.getEntryPoint().toString());
        result.put("name", function.getName());
        result.put("body", function.getBody().toString());
        result.put("mode", mode);
        result.put("signature", function.getPrototypeString(false, false));
        result.put("instructions", instructions);
        return result;
    }

    private void global(Address address, String name, DataType type) throws Exception {
        DataUtilities.createData(currentProgram, address, type, type.getLength(),
            DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
        currentProgram.getSymbolTable().createLabel(address, name, SourceType.USER_DEFINED).setPrimary();
    }
}
