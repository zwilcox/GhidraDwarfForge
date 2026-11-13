// Explicit analyst-only peripheral map. No register contents or effects are inferred.
// @category DWARF.Tests
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

public class PrepareRawMmio extends GhidraScript {
    @Override protected void run() throws Exception {
        if (getScriptArgs().length != 1) throw new IllegalArgumentException("selection output required");
        var address = toAddr(0x40001000);
        var block = currentProgram.getMemory().createUninitializedBlock("analyst-peripheral", address, 4, false);
        block.setPermissions(true, false, false);
        block.setVolatile(true);
        var manager = currentProgram.getDataTypeManager();
        var category = new CategoryPath("/RawMmioFixture");
        var unsigned = new UnsignedIntegerDataType(manager);
        var fields = new StructureDataType(category, "RawStatusBits", 0, manager);
        fields.setPackingEnabled(true);
        fields.addBitField(unsigned, 3, "mode", null);
        fields.addBitField(unsigned, 1, "ready", null);
        fields.addBitField(unsigned, 28, "reserved", null);
        var union = new UnionDataType(category, "RawStatus", manager);
        union.add(unsigned, "raw", null);
        union.add(fields, "bits", null);
        var type = manager.resolve(union, DataTypeConflictHandler.REPLACE_HANDLER);
        if (type.getLength() != 4) throw new AssertionError("unexpected raw register layout");
        DataUtilities.createData(currentProgram, address, type, 4, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
        currentProgram.getSymbolTable().createLabel(address, "analyst_status", SourceType.USER_DEFINED).setPrimary();
        var scalar = manager.resolve(unsigned, DataTypeConflictHandler.REPLACE_HANDLER);
        var selection = Map.of("schema", 1, "language", currentProgram.getLanguageID().getIdAsString(),
            "architecture", "armv7", "transport", Map.of("id", "unproved-device", "evidence",
                "No device access contract: unknown policy must prohibit every snapshot"),
            "registers", List.of(Map.of("name", "status", "address", address.toString(true),
                "runtime_address", "0x40001000", "width", 4, "read_effect", "unknown", "views", List.of(
                    Map.of("name", "register", "datatype", type.getPathName(), "offset", 0,
                        "qualifiers", List.of("const", "volatile")),
                    Map.of("name", "scalar", "datatype", scalar.getPathName(), "offset", 0,
                        "qualifiers", List.of("volatile"))))));
        Path file = Path.of(getScriptArgs()[0]);
        Files.writeString(file, new com.google.gson.Gson().toJson(selection));
        runScript("GhidraDwarfForgeMmioProfile.java", new String[] {file.toString()});
        if (block.isInitialized()) throw new AssertionError("peripheral contents must remain unknown");
        println("raw-mmio-selection=PASS");
    }
}
