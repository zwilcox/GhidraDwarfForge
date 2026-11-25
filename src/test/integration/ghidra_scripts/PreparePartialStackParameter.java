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
        var memory = currentProgram.getMemory();
        memory.split(memory.getBlock(entry), entry.add(4));
        currentProgram.getListing().clearCodeUnits(entry.add(4), last, false);
        function.setBody(new AddressSet(entry, last));
        function.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.USER_DEFINED,
            new ParameterImpl("stack_argument", IntegerDataType.dataType, 8, currentProgram, SourceType.USER_DEFINED));
        if (currentProgram.getListing().getInstructions(new AddressSet(entry.add(4), last), true).hasNext()) {
            throw new AssertionError("undecoded tail fixture contains an instruction");
        }
        var overlay = memory.createInitializedBlock("overlay_bank", entry, 32,
            (byte) 0, monitor, true);
        currentProgram.getFunctionManager().createFunction("overlay_only", currentProgram.getGlobalNamespace(),
            overlay.getStart(), new AddressSet(overlay.getStart(), overlay.getEnd()), SourceType.USER_DEFINED);
        var sibling = memory.createInitializedBlock("second_bank", entry, 32, (byte) 0, monitor, true);
        var table = currentProgram.getSymbolTable();
        var owner = currentProgram.getFunctionManager().createFunction(function.getName(),
            table.createNameSpace(currentProgram.getGlobalNamespace(), "bank", SourceType.USER_DEFINED),
            sibling.getStart(), new AddressSet(sibling.getStart(), sibling.getEnd()), SourceType.USER_DEFINED);
        var storage = toAddr(getScriptArgs()[1]);
        clearListing(storage, storage.add(7));
        createData(storage, IntegerDataType.dataType);
        createData(storage.add(4), IntegerDataType.dataType);
        table.createLabel(storage, "bank_private", owner, SourceType.USER_DEFINED);
        table.createLabel(storage.add(4), "real_private", function, SourceType.USER_DEFINED);
        var extra = memory.createInitializedBlock("analysis_scratch", toAddr(0x61000000L), 32,
            (byte) 0, monitor, false);
        extra.setExecute(true);
        currentProgram.getFunctionManager().createFunction("analysis_block_only", currentProgram.getGlobalNamespace(),
            extra.getStart(), new AddressSet(extra.getStart(), extra.getEnd()), SourceType.USER_DEFINED);
        println("partial-stack-first-instruction=PASS");
    }
}
