// Curates the tiny x86-64 fixture before repeated saved-program exports.
// @category DWARF.Tests

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;

public class PreparePathTraversal extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 4 || currentProgram.getDefaultPointerSize() != 8 ||
                !currentProgram.getLanguage().getProcessor().toString().equals("x86")) {
            throw new IllegalArgumentException("expected x86-64 <add-address> <add-size> <main-address> <main-size>");
        }
        Function add = fixtureFunction(args[0], args[1]);
        Function main = fixtureFunction(args[2], args[3]);
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

    private Function fixtureFunction(String address, String size) throws Exception {
        var entry = toAddr(Long.decode(address));
        int bytes = Integer.parseInt(size);
        if (bytes <= 0) throw new IllegalArgumentException("empty compiler fixture function at " + entry);
        var function = getFunctionAt(entry);
        if (function != null) return function;
        // The stripped fixture can have only a label here. The matching reference ELF supplies the body.
        if (getInstructionAt(entry) == null && !disassemble(entry)) {
            throw new IllegalStateException("cannot disassemble compiler fixture function at " + entry);
        }
        var body = new AddressSet(entry, entry.addNoWrap(bytes - 1L));
        return currentProgram.getFunctionManager().createFunction(null, entry, body, SourceType.USER_DEFINED);
    }
}
