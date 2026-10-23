// Applies an explicit signature/global type for the nonzero-load-offset fixture.
// @category DWARF.Tests

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;

public class PrepareNonzeroLoadOffset extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 2) {
            throw new IllegalArgumentException("usage: PrepareNonzeroLoadOffset <function> <global>");
        }
        Function function = getFunctionAt(toAddr(arguments[0]));
        if (function == null) {
            throw new IllegalStateException("fixture function was not discovered");
        }
        DataType signedInt = new IntegerDataType(currentProgram.getDataTypeManager());
        function.setName("nonzero_add", SourceType.USER_DEFINED);
        function.setCallingConvention(Function.DEFAULT_CALLING_CONVENTION_STRING);
        function.setReturnType(signedInt, SourceType.USER_DEFINED);
        // This source-built fixture uses the x86-64 SysV ABI and preserves
        // both incoming registers throughout nonzero_add.
        var leftRegister = currentProgram.getRegister("EDI");
        var rightRegister = currentProgram.getRegister("ESI");
        if (leftRegister == null || rightRegister == null) {
            throw new IllegalStateException("fixture requires x86-64 SysV argument registers");
        }
        function.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE,
            true, SourceType.USER_DEFINED,
            new ParameterImpl("left", signedInt, leftRegister, currentProgram,
                SourceType.USER_DEFINED),
            new ParameterImpl("right", signedInt, rightRegister, currentProgram,
                SourceType.USER_DEFINED));
        var address = toAddr(arguments[1]);
        DataUtilities.createData(currentProgram, address, signedInt, signedInt.getLength(),
            DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
        currentProgram.getSymbolTable().createLabel(address, "nonzero_sink",
            SourceType.USER_DEFINED).setPrimary();
        println("Prepared nonzero_add and nonzero_sink at " + arguments[0] + "/" + arguments[1]);
    }
}
