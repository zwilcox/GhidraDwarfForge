// Applies exact assembler-defined function bodies, entries and stable parameters.
// @category DWARF.Tests

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.AddressNormalizer;
import ghidradwarfforge.GhidraImageBase;

public class PrepareFunctionEntryRanges extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 9) {
            throw new IllegalArgumentException("expected seven body labels and two globals");
        }
        long delta = AddressNormalizer.rebaseDelta(currentProgram.getImageBase().getOffset(),
            GhidraImageBase.originalImageBase(currentProgram));
        Address[] addresses = new Address[arguments.length];
        for (int index = 0; index < arguments.length; index++) {
            addresses[index] = toAddr(Math.addExact(Long.decode(arguments[index]), delta));
        }
        AddressSet below = new AddressSet(addresses[0], addresses[1].subtract(1));
        below.add(addresses[2], addresses[3].subtract(1));
        AddressSet middle = new AddressSet(addresses[4], addresses[6].subtract(1));
        prepare("recovered_below", addresses[2], below);
        prepare("recovered_middle", addresses[5], middle);
        for (int index = 7; index < 9; index++) {
            var type = new IntegerDataType(currentProgram.getDataTypeManager());
            DataUtilities.createData(currentProgram, addresses[index], type, type.getLength(),
                DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
            currentProgram.getSymbolTable().createLabel(addresses[index],
                index == 7 ? "below_sink" : "middle_sink", SourceType.USER_DEFINED).setPrimary();
        }
        println("function-entry-preparation=PASS delta=0x" + Long.toHexString(delta));
    }

    private void prepare(String name, Address entry, AddressSet body) throws Exception {
        var manager = currentProgram.getFunctionManager();
        // Auto-analysis may create separate functions at backward branch targets.
        // The test's assembler labels establish their actual shared ownership.
        var overlaps = manager.getFunctionsOverlapping(body);
        var remove = new java.util.ArrayList<Address>();
        while (overlaps.hasNext()) {
            remove.add(overlaps.next().getEntryPoint());
        }
        for (Address address : remove) {
            manager.removeFunction(address);
        }
        disassemble(entry);
        disassemble(body.getMinAddress());
        // Auto-analysis may have classified the backward branch as a tail
        // call to the old separate function. Restore the actual instruction
        // semantics now that the assembler-proven body is one function.
        var instructions = currentProgram.getListing().getInstructions(body, true);
        while (instructions.hasNext()) {
            instructions.next().setFlowOverride(ghidra.program.model.listing.FlowOverride.NONE);
        }
        Function function = manager.createFunction(name, entry, body, SourceType.USER_DEFINED);
        if (function == null || !function.getBody().equals(body) ||
                !function.getEntryPoint().equals(entry)) {
            throw new IllegalStateException("curated entry/body was not retained");
        }
        var type = new IntegerDataType(currentProgram.getDataTypeManager());
        function.setReturnType(type, SourceType.USER_DEFINED);
        function.setCallingConvention(Function.DEFAULT_CALLING_CONVENTION_STRING);
        // This x86-64 fixture never clobbers either incoming argument register.
        function.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE,
            true, SourceType.USER_DEFINED,
            new ParameterImpl("left", type, currentProgram.getRegister("EDI"),
                currentProgram, SourceType.USER_DEFINED),
            new ParameterImpl("right", type, currentProgram.getRegister("ESI"),
                currentProgram, SourceType.USER_DEFINED));
        println(name + " entry=" + entry + " body=" + body);
    }
}
