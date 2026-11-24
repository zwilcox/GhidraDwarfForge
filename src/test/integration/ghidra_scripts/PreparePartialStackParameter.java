// Keep only the first stack adjustment decoded in a 32-byte x86-64 function.
// @category DWARF.Tests
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;

public class PreparePartialStackParameter extends GhidraScript {
    @Override protected void run() throws Exception {
        var entry = toAddr(getScriptArgs()[0]);
        var last = entry.add(31);
        var function = getFunctionAt(entry);
        if (function == null || getInstructionAt(entry).getLength() != 4) {
            throw new IllegalStateException("expected the x86-64 four-byte sub rsp,32");
        }
        currentProgram.getListing().clearCodeUnits(entry.add(4), last, false);
        function.setBody(new AddressSet(entry, last));
        function.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.USER_DEFINED,
            new ParameterImpl("stack_argument", IntegerDataType.dataType, 8, currentProgram, SourceType.USER_DEFINED));
        if (currentProgram.getListing().getInstructions(new AddressSet(entry.add(4), last), true).hasNext()) {
            throw new AssertionError("undecoded tail fixture contains an instruction");
        }
        var overlay = currentProgram.getMemory().createInitializedBlock("overlay_bank", entry, 32,
            (byte) 0, monitor, true);
        currentProgram.getFunctionManager().createFunction("overlay_only", currentProgram.getGlobalNamespace(),
            overlay.getStart(), new AddressSet(overlay.getStart(), overlay.getEnd()), SourceType.USER_DEFINED);
        println("partial-stack-first-instruction=PASS");
    }
}
