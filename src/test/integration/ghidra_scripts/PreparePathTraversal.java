// Curates the tiny x86-64 fixture before repeated saved-program exports.
// @category DWARF.Tests

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;

public class PreparePathTraversal extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2 || currentProgram.getDefaultPointerSize() != 8 ||
                !currentProgram.getLanguage().getProcessor().toString().equals("x86")) {
            throw new IllegalArgumentException("expected x86-64 <add-address> <main-address>");
        }
        Function add = getFunctionAt(toAddr(Long.decode(args[0])));
        Function main = getFunctionAt(toAddr(Long.decode(args[1])));
        if (add == null || main == null) {
            throw new IllegalStateException("compiler fixture function missing");
        }
        var type = new IntegerDataType(currentProgram.getDataTypeManager());
        add.setName("analyst_add", SourceType.USER_DEFINED);
        add.setReturnType(type, SourceType.USER_DEFINED);
        add.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE, true,
            SourceType.USER_DEFINED,
            new ParameterImpl("left", type, currentProgram.getRegister("EDI"), currentProgram),
            new ParameterImpl("right", type, currentProgram.getRegister("ESI"), currentProgram));
        main.setName("main", SourceType.USER_DEFINED);
        main.setReturnType(type, SourceType.USER_DEFINED);
        println("path-traversal-preparation=PASS");
    }
}
