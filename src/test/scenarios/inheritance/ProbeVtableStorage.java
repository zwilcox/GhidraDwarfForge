// Observe actual loaded/file bytes and relocation records before/after rebasing.
// @category DWARF.Tests
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonParser;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidradwarfforge.GhidraImageBase;

public class ProbeVtableStorage extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (getScriptArgs().length != 2) throw new IllegalArgumentException("vtables.json result.json");
        var tables = JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonArray();
        long originalBase = GhidraImageBase.originalImageBase(currentProgram);
        long loadedBase = currentProgram.getImageBase().getOffset();
        var before = observe(tables, originalBase);
        currentProgram.setImageBase(currentProgram.getImageBase().add(0x200000), true);
        var after = observe(tables, originalBase);
        Files.writeString(Path.of(getScriptArgs()[1]), new GsonBuilder().setPrettyPrinting().create().toJson(
            Map.of("originalBase", originalBase, "loadedBase", loadedBase,
                "rebasedBase", currentProgram.getImageBase().getOffset(), "before", before, "after", after)) + "\n");
        println("vtable-storage-observation=PASS");
    }

    private ArrayList<Object> observe(JsonArray tables, long originalBase) throws Exception {
        var observations = new ArrayList<Object>();
        long delta = currentProgram.getImageBase().getOffset() - originalBase;
        var memory = currentProgram.getMemory();
        for (var item : tables) {
            monitor.checkCancelled();
            var row = item.getAsJsonObject();
            int size = row.get("size").getAsInt();
            if (size <= 0 || size > 65536) throw new AssertionError("unexpected fixture vtable extent");
            var address = currentProgram.getAddressFactory().getDefaultAddressSpace()
                .getAddress(row.get("address").getAsLong() + delta);
            byte[] loaded = new byte[size], original = new byte[size];
            if (memory.getBytes(address, loaded) != size) throw new AssertionError("incomplete memory read");
            long firstOffset = -1;
            for (int index = 0; index < size; index++) {
                monitor.checkCancelled();
                var at = address.add(index);
                var info = memory.getAddressSourceInfo(at);
                if (info == null) throw new AssertionError("missing file mapping");
                var source = info.getMemoryBlockSourceInfo();
                var file = source.getFileBytes().orElseThrow();
                long offset = source.getFileBytesOffset(at);
                if (offset < 0 || source.getMappedRange().isPresent()) throw new AssertionError("nonlinear mapping");
                long absolute = Math.addExact(file.getFileOffset(), offset);
                if (index == 0) firstOffset = absolute;
                if (absolute != firstOffset + index) throw new AssertionError("noncontiguous original bytes");
                original[index] = file.getOriginalByte(offset);
            }
            var relocations = new ArrayList<Object>();
            var iterator = currentProgram.getRelocationTable().getRelocations(new AddressSet(address, address.add(size - 1)));
            while (iterator.hasNext()) {
                monitor.checkCancelled();
                var relocation = iterator.next();
                var entry = new LinkedHashMap<String, Object>();
                entry.put("offset", relocation.getAddress().subtract(address));
                entry.put("type", relocation.getType()); entry.put("status", relocation.getStatus().name());
                entry.put("values", relocation.getValues()); entry.put("symbol", relocation.getSymbolName());
                entry.put("originalBytes", relocation.getBytes() == null ? null : HexFormat.of().formatHex(relocation.getBytes()));
                relocations.add(entry);
            }
            observations.add(Map.of("name", row.get("name").getAsString(), "address", address.getOffset(),
                "originalAddress", row.get("address").getAsLong(), "fileOffset", firstOffset,
                "loadedBytes", HexFormat.of().formatHex(loaded), "originalBytes", HexFormat.of().formatHex(original),
                "relocations", relocations));
        }
        return observations;
    }
}
