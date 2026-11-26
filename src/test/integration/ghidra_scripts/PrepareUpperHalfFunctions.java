// Apply the source-known signatures and global in the two-segment ELF fixture.
// @category DWARF.Tests
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;

public class PrepareUpperHalfFunctions extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3) throw new IllegalArgumentException("expected low function, high function and global");
        var signed = new IntegerDataType(currentProgram.getDataTypeManager());
        Function low = define(args[0], "curated_low");
        Function high = define(args[1], "curated_high");
        low.setReturnType(signed, SourceType.USER_DEFINED);
        high.setReturnType(signed, SourceType.USER_DEFINED);
        high.setCallingConvention(Function.DEFAULT_CALLING_CONVENTION_STRING);
        high.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED,
            new ParameterImpl("left", signed, currentProgram), new ParameterImpl("right", signed, currentProgram));
        var object = toAddr(args[2]);
        clearListing(object, object.add(3));
        createData(object, signed);
        createLabel(object, "curated_word", true, SourceType.USER_DEFINED);
    }

    private Function define(String address, String name) throws Exception {
        var entry = toAddr(address);
        if (getInstructionAt(entry) == null && !disassemble(entry)) throw new AssertionError("cannot decode " + entry);
        var function = getFunctionAt(entry);
        if (function == null) function = createFunction(entry, name);
        if (function == null) throw new AssertionError("cannot create function at " + entry);
        function.setName(name, SourceType.USER_DEFINED);
        return function;
    }
}
