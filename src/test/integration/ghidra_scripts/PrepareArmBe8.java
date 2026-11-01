// Apply source-known scalar types to an independently compiled BE8 fixture.
// @category DWARF.Tests
import com.google.gson.Gson;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;

public class PrepareArmBe8 extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) throw new IllegalArgumentException("function and global addresses required");
        var entry = toAddr(Long.decode(args[0]));
        var global = toAddr(Long.decode(args[1]));
        var language = currentProgram.getLanguage();
        if (!language.isBigEndian() || language.getLanguageDescription().getInstructionEndian() !=
                ghidra.program.model.lang.Endian.LITTLE) {
            throw new IllegalStateException("expected BE8 data/instruction encoding");
        }
        var function = getFunctionAt(entry);
        if (function == null || function.getBody().getNumAddresses() != 52 ||
                function.getBody().getNumAddressRanges() != 1) {
            throw new IllegalStateException("unexpected independently compiled scalar function");
        }
        var type = new UnsignedIntegerDataType(currentProgram.getDataTypeManager());
        function.setName("recovered_be8_probe", SourceType.USER_DEFINED);
        function.setCallingConvention(Function.DEFAULT_CALLING_CONVENTION_STRING);
        function.setReturnType(type, SourceType.USER_DEFINED);
        function.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
            true, SourceType.USER_DEFINED,
            new ParameterImpl("value", type, currentProgram, SourceType.USER_DEFINED));
        DataUtilities.createData(currentProgram, global, type, 4,
            DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
        currentProgram.getSymbolTable().createLabel(global, "be8_global", SourceType.USER_DEFINED).setPrimary();
        if (getInt(global) != 0x11223344) throw new IllegalStateException("wrong global byte order");
        var rows = new ArrayList<Object>();
        for (int offset = 0; offset < 52; offset += 4) {
            var instruction = getInstructionAt(entry.add(offset));
            if (instruction == null || instruction.getLength() != 4) {
                throw new IllegalStateException("missing instruction at " + offset);
            }
            rows.add(java.util.Map.of("offset", offset, "text", instruction.toString(),
                "bytes", java.util.HexFormat.of().formatHex(instruction.getBytes())));
        }
        var result = new LinkedHashMap<String, Object>();
        result.put("language", currentProgram.getLanguageID().toString());
        result.put("compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        result.put("entry", entry.toString());
        result.put("global", global.toString());
        result.put("parameterStorage", function.getParameter(0).getVariableStorage().toString());
        result.put("returnStorage", function.getReturn().getVariableStorage().toString());
        result.put("instructions", rows);
        println("ARM_BE8_MODEL=" + new Gson().toJson(result));
    }
}
