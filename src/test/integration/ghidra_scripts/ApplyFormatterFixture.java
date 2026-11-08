// Explicit analyst choices for the formatter fixture; compiler DWARF is absent.
// @category DWARF.Tests
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import java.nio.file.Files;
import java.nio.file.Path;

public class ApplyFormatterFixture extends GhidraScript {
    private com.google.gson.JsonObject addresses;
    private long delta;

    @Override
    protected void run() throws Exception {
        if (getScriptArgs().length != 3) throw new IllegalArgumentException("selection output, compiler symbol map and original ELF required");
        addresses = com.google.gson.JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[1]))).getAsJsonObject();
        delta = currentProgram.getImageBase().getOffset() - ghidradwarfforge.elf.ElfImage.read(
            Path.of(getScriptArgs()[2])).preferredImageBase();
        var marker = getFunctionAt(address("forge_formatter_marker"));
        if (marker == null) throw new IllegalStateException("formatter fixture marker was not analyzed");
        marker.setName("forge_formatter_marker", ghidra.program.model.symbol.SourceType.USER_DEFINED);
        var manager = currentProgram.getDataTypeManager();
        var category = new CategoryPath("/ForgeFormatterFixture");
        var flags = new EnumDataType(category, "ForgeFlags", 4, manager);
        flags.add("FORGE_NONE", 0);
        flags.add("FORGE_READ", 1);
        flags.add("FORGE_READ_ALIAS", 1);
        flags.add("FORGE_WRITE", 2);
        flags.add("FORGE_BOTH", 3);
        flags.add("FORGE_HIGH", 0x80000000L);
        flags.add("TEXT_\"\\\nλ\u001b[31m;raise RuntimeError('analyst text executed')", 16);
        var savedFlags = manager.resolve(flags, DataTypeConflictHandler.REPLACE_HANDLER);
        marker.addLocalVariable(new ghidra.program.model.listing.LocalVariableImpl(
            "forge_unavailable", 0, savedFlags, ghidra.program.model.listing.VariableStorage.UNASSIGNED_STORAGE,
            false, currentProgram, ghidra.program.model.symbol.SourceType.USER_DEFINED),
            ghidra.program.model.symbol.SourceType.USER_DEFINED);
        var node = new StructureDataType(category, "ForgeNode", 0, manager);
        node.setPackingEnabled(true);
        node.addBitField(new UnsignedIntegerDataType(manager), 3, "a", null);
        node.addBitField(new UnsignedIntegerDataType(manager), 5, "b", null);
        node.add(new IntegerDataType(manager), "value", null);
        node.add(new PointerDataType(node, manager), "next", null);
        node.add(new PointerDataType(node, manager), "unreadable", null);
        var savedNode = manager.resolve(node, DataTypeConflictHandler.REPLACE_HANDLER);
        for (String name : new String[] {"forge_flags", "forge_zero", "forge_combined", "forge_high", "forge_text"}) {
            apply(name, savedFlags);
        }
        apply("forge_node", savedNode);
        manager.setFavorite(savedFlags, true);
        manager.setFavorite(savedNode, true);
        var types = new java.util.ArrayList<java.util.Map<String, String>>();
        types.add(java.util.Map.of("key", "uid:" + Long.toUnsignedString(savedFlags.getUniversalID().getValue(), 16), "mode", "flags"));
        types.add(java.util.Map.of("key", "uid:" + Long.toUnsignedString(savedNode.getUniversalID().getValue(), 16), "mode", "structure"));
        for (var spec : new Object[][] {
                {"ForgeSigned8", "forge_signed8", "SIGNED8", 1, -128L},
                {"ForgeUnsigned16", "forge_unsigned16", "UNSIGNED16", 2, 32768L},
                {"ForgeUnsigned64", "forge_unsigned64", "UNSIGNED64", 8, 0x4000000000000000L},
                {"ForgeSigned64", "forge_signed64", "SIGNED64", 8, Long.MIN_VALUE}}) {
            var enumeration = new EnumDataType(category, (String) spec[0], (Integer) spec[3], manager);
            enumeration.add(spec[2] + "_ZERO", 0);
            enumeration.add(spec[2] + "_LOW", 1);
            enumeration.add(spec[2] + "_HIGH", (Long) spec[4]);
            var saved = manager.resolve(enumeration, DataTypeConflictHandler.REPLACE_HANDLER);
            apply((String) spec[1], saved);
            types.add(java.util.Map.of("key", "uid:" + Long.toUnsignedString(saved.getUniversalID().getValue(), 16), "mode", "flags"));
        }
        var branch = new StructureDataType(category, "ForgeBranch", 0, manager);
        branch.setPackingEnabled(true);
        branch.add(savedNode, "node", null);
        branch.add(new IntegerDataType(manager), "tail", null);
        var envelope = new StructureDataType(category, "ForgeEnvelope", 0, manager);
        envelope.setPackingEnabled(true);
        envelope.add(branch, "branch", null);
        envelope.add(new PointerDataType(savedNode, manager), "nil", null);
        envelope.add(new ghidra.program.model.data.ArrayDataType(
            new ghidra.program.model.data.UnsignedCharDataType(manager), 12, 1, manager), "octets", null);
        var savedEnvelope = manager.resolve(envelope, DataTypeConflictHandler.REPLACE_HANDLER);
        apply("forge_envelope", savedEnvelope);
        types.add(java.util.Map.of("key", "uid:" + Long.toUnsignedString(savedEnvelope.getUniversalID().getValue(), 16), "mode", "structure"));
        for (boolean ambiguous : new boolean[] {false, true}) {
            for (boolean other : new boolean[] {false, true}) {
                var scope = new CategoryPath("/ForgeFormatterFixture/" + (other ? "Other" : "Selected"));
                var scoped = new StructureDataType(scope, ambiguous ? "ForgeAmbiguous" : "ForgeChoice", 0, manager);
                scoped.add(other && !ambiguous ? new ghidra.program.model.data.LongLongDataType(manager) :
                    new IntegerDataType(manager), ambiguous ? "member" : other ? "other" : "selected", null);
                var saved = manager.resolve(scoped, DataTypeConflictHandler.REPLACE_HANDLER);
                apply("forge_" + (other ? "other_" : "") + (ambiguous ? "ambiguous" : "choice"), saved);
                if (!other) types.add(java.util.Map.of("key", "uid:" +
                    Long.toUnsignedString(saved.getUniversalID().getValue(), 16), "mode", "structure"));
            }
        }
        Files.writeString(Path.of(getScriptArgs()[0]), new com.google.gson.Gson().toJson(java.util.Map.of("schema", 1, "types", types)));
        println("formatter-fixture=PASS nodeSize=" + savedNode.getLength());
    }

    private void apply(String name, DataType type) throws Exception {
        var address = address(name);
        DataUtilities.createData(currentProgram, address, type, type.getLength(),
            DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
        currentProgram.getSymbolTable().createLabel(address, name,
            ghidra.program.model.symbol.SourceType.USER_DEFINED).setPrimary();
    }

    private ghidra.program.model.address.Address address(String name) {
        return toAddr(Math.addExact(Long.parseUnsignedLong(addresses.get(name).getAsString(), 16), delta));
    }
}
