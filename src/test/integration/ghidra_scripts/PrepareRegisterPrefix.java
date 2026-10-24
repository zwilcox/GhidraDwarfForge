// Applies the compiler-oracle incoming parameter and global type.
// @category DWARF.Tests

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.AddressNormalizer;
import ghidradwarfforge.GhidraImageBase;

public class PrepareRegisterPrefix extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3) {
            throw new IllegalArgumentException("expected <function> <sink> <register>");
        }
        long delta = AddressNormalizer.rebaseDelta(currentProgram.getImageBase().getOffset(),
            GhidraImageBase.originalImageBase(currentProgram));
        var entry = toAddr(Math.addExact(Long.decode(args[0]), delta));
        Function function = getFunctionAt(entry);
        if (function == null) {
            throw new IllegalStateException("missing fixture function");
        }
        function.setName("prefix_value", SourceType.USER_DEFINED);
        var type = new IntegerDataType(currentProgram.getDataTypeManager());
        function.setReturnType(type, SourceType.USER_DEFINED);
        function.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE, true,
            SourceType.USER_DEFINED, new ParameterImpl("value", type,
                currentProgram.getRegister(args[2]), currentProgram, SourceType.USER_DEFINED));
        var sink = toAddr(Math.addExact(Long.decode(args[1]), delta));
        DataUtilities.createData(currentProgram, sink, type, type.getLength(),
            DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
        currentProgram.getSymbolTable().createLabel(sink, "prefix_sink",
            SourceType.USER_DEFINED).setPrimary();
        println("register-prefix-preparation=PASS " + function.getBody());
    }
}
