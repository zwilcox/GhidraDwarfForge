// Applies compiler-matched bit-field types without importing compiler DWARF.
// @category DWARF.Tests

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.symbol.SourceType;

public class ApplyBitFieldFixture extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 3) {
            throw new IllegalArgumentException(
                "usage: ApplyBitFieldFixture <inspect-address> <word-address> <byte-address>");
        }
        var function = getFunctionAt(toAddr(arguments[0]));
        if (function == null) {
            throw new IllegalStateException("missing inspect_flags function");
        }
        function.setName("inspect_flags", SourceType.USER_DEFINED);
        DataTypeManager manager = currentProgram.getDataTypeManager();
        for (boolean packed : new boolean[] { false, true }) {
            String name = packed ? "byte_flags" : "word_flags";
            StructureDataType structure = new StructureDataType(
                new CategoryPath("/ForgeBitFieldFixture"), name, 0, manager);
            structure.setPackingEnabled(true);
            if (packed) {
                structure.setExplicitPackingValue(1);
            }
            DataType base = new UnsignedIntegerDataType(manager);
            structure.addBitField(base, 3, "a", null);
            structure.addBitField(base, 5, "b", null);
            Structure resolved = (Structure) manager.resolve(structure,
                DataTypeConflictHandler.REPLACE_HANDLER);
            if (base.getLength() != 4 || resolved.getLength() != (packed ? 1 : 4)) {
                throw new IllegalStateException("unexpected bit-field aggregate layout");
            }
            for (DataTypeComponent component : resolved.getDefinedComponents()) {
                BitFieldDataType bits = (BitFieldDataType) component.getDataType();
                if (component.getLength() != 1 || bits.getStorageSize() != 1 ||
                        bits.getBaseTypeSize() != 4 || component.getOffset() != 0) {
                    throw new IllegalStateException("fixture must exercise one-byte component storage");
                }
                println(name + "." + component.getFieldName() + " storage=" +
                    bits.getStorageSize() + " base=" + bits.getBaseTypeSize() +
                    " lsb=" + bits.getBitOffset() + " bits=" + bits.getBitSize());
            }
            String variable = packed ? "byte_value" : "word_value";
            var address = toAddr(arguments[packed ? 2 : 1]);
            DataUtilities.createData(currentProgram, address, resolved, resolved.getLength(),
                DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
            currentProgram.getSymbolTable().createLabel(address, variable,
                SourceType.USER_DEFINED).setPrimary();
            manager.setFavorite(resolved, true);
        }
    }
}
