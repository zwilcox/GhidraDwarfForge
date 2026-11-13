// Applies analyst register types without importing compiler debug information.
// @category DWARF.Tests

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.SourceType;

public class ApplyMmioFixture extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (getScriptArgs().length != 1) throw new IllegalArgumentException("main address required");
        var function = getFunctionAt(toAddr(getScriptArgs()[0]));
        if (function == null) throw new IllegalStateException("missing fixture main");
        function.setName("main", SourceType.USER_DEFINED);
        var manager = currentProgram.getDataTypeManager();
        var category = new CategoryPath("/ForgeMmioFixture");
        DataType unsigned = new UnsignedIntegerDataType(manager);
        DataType signed = new IntegerDataType(manager);
        var word = new TypedefDataType(category, "word32", unsigned, manager);
        var bits = new StructureDataType(category, "Fields", 0, manager);
        bits.setPackingEnabled(true);
        bits.addBitField(unsigned, 3, "a", null);
        bits.addBitField(unsigned, 5, "b", null);
        bits.addBitField(unsigned, 24, "reserved", null);
        var packed = new StructureDataType(category, "ByteFields", 0, manager);
        packed.setPackingEnabled(true);
        packed.setExplicitPackingValue(1);
        packed.addBitField(unsigned, 3, "a", null);
        packed.addBitField(unsigned, 5, "b", null);
        var cross = new StructureDataType(category, "CrossFields", 0, manager);
        cross.setPackingEnabled(true);
        cross.addBitField(unsigned, 6, "prefix", null);
        cross.addBitField(unsigned, 7, "cross", null);
        cross.addBitField(signed, 3, "sign", null);
        cross.addBitField(unsigned, 16, "reserved", null);
        var flags = new EnumDataType(category, "StatusFlags", 4, manager);
        flags.add("STATUS_READY", 1);
        flags.add("STATUS_BUSY", 8);
        flags.add("STATUS_ERROR", 128);
        var register = new UnionDataType(category, "Register", manager);
        register.add(word, "raw", null);
        register.add(bits, "bits", null);
        register.add(packed, "byte", null);
        register.add(cross, "cross", null);
        register.add(flags, "flags", null);
        var device = new StructureDataType(category, "Device", 0, manager);
        device.add(register, "status", null);
        device.add(word, "counter", null);
        var resolved = (Structure) manager.resolve(device, DataTypeConflictHandler.REPLACE_HANDLER);
        if (resolved.getLength() != 8 || resolved.getComponent(1).getOffset() != 4 ||
                packed.getLength() != 1 || register.getLength() != 4) {
            throw new IllegalStateException("unexpected MMIO type layout");
        }
        // Ghidra has one mutability mode, not independent const/volatile flags.
        MutabilitySettingsDefinition.DEF.setChoice(resolved.getComponent(0).getDefaultSettings(),
            MutabilitySettingsDefinition.CONSTANT);
        MutabilitySettingsDefinition.DEF.setChoice(resolved.getComponent(1).getDefaultSettings(),
            MutabilitySettingsDefinition.VOLATILE);
        var address = toAddr(0x40000000L);
        var data = DataUtilities.createData(currentProgram, address, resolved, resolved.getLength(),
            DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
        MutabilitySettingsDefinition.DEF.setChoice(data, MutabilitySettingsDefinition.VOLATILE);
        var block = currentProgram.getMemory().getBlock(address);
        block.setVolatile(true);
        currentProgram.getSymbolTable().createLabel(address, "peripheral", SourceType.USER_DEFINED).setPrimary();
        currentProgram.getSymbolTable().createLabel(address, "peripheral_alias", SourceType.USER_DEFINED);
        String architecture = currentProgram.getLanguageID().getIdAsString().startsWith("x86:")
            ? "i386:x86-64" : "mips:isa32r2";
        var standalone = new StructureDataType(category, "IndependentByteView", 0, manager);
        standalone.setPackingEnabled(true);
        standalone.setExplicitPackingValue(1);
        standalone.addBitField(unsigned, 3, "a", null);
        standalone.addBitField(unsigned, 5, "b", null);
        var independent = manager.resolve(standalone, DataTypeConflictHandler.REPLACE_HANDLER);
        var selection = java.util.Map.of("schema", 1,
            "language", currentProgram.getLanguageID().getIdAsString(), "architecture", architecture,
            "transport", java.util.Map.of("id", "instrumented-word32", "evidence",
                "Source-modeled Target/Device callback trace in mmio-access/helper.py; no physical bus claim"),
            "registers", java.util.List.of(java.util.Map.of("name", "status", "address", address.toString(true),
                "runtime_address", "0x40000000", "width", 4, "read_effect", "read-clear", "views", java.util.List.of(
                    java.util.Map.of("name", "register", "datatype", data.getComponent(0).getDataType().getPathName(),
                        "offset", 0, "qualifiers", java.util.List.of("const", "volatile")),
                    java.util.Map.of("name", "packed", "datatype", independent.getPathName(),
                        "offset", 0, "qualifiers", java.util.List.of("const"))))));
        String selected = new com.google.gson.Gson().toJson(selection);
        var selectionPath = java.nio.file.Path.of(currentProgram.getExecutablePath()).resolveSibling("analyst-mmio.json");
        java.nio.file.Files.writeString(selectionPath, selected);
        runScript("GhidraDwarfForgeMmioProfile.java", new String[] { selectionPath.toString() });
        if (!selected.equals(currentProgram.getOptions(ghidradwarfforge.GhidraMmioProfile.OPTIONS)
                .getString(ghidradwarfforge.GhidraMmioProfile.SELECTION, null))) {
            throw new IllegalStateException("configuration script did not retain selected MMIO profile");
        }
        println("MMIO_MUTABILITY aggregate=" + data.isVolatile() + " status=" +
            data.getComponent(0).isConstant() + " counter=" + data.getComponent(1).isVolatile());
        println("MMIO_CURATION=PASS address=" + address + " size=" + data.getLength());
    }
}
