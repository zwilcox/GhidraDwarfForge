// Save explicit compiler-fixture table evidence and exercise the production snapshot API.
// @category DWARF.Tests
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonParser;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolType;
import ghidradwarfforge.GhidraImageBase;
import ghidradwarfforge.GhidraVtableBindings;
import ghidradwarfforge.GhidraVtableBindings.*;

public class ProbeVtableBindings extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (getScriptArgs().length < 2 || getScriptArgs().length > 3) throw new IllegalArgumentException("vtables.json result.json [save-only]");
        boolean saveOnly = getScriptArgs().length == 3 && getScriptArgs()[2].equals("save-only");
        if (getScriptArgs().length == 3 && !saveOnly) throw new IllegalArgumentException("unknown fixture mode");
        var tables = JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[0]))).getAsJsonArray();
        // Explicit source-built fixture geometry; never a production table-scanning heuristic.
        var geometry = Map.of(
            "_ZTV6Single", new long[][] {{16, 0}},
            "_ZTV8Multiple", new long[][] {{16, 0}, {48, 16}},
            "_ZTV11VirtualBase", new long[][] {{16, 0}},
            "_ZTV11VirtualLeft", new long[][] {{24, 0}, {56, 16}},
            "_ZTV12VirtualRight", new long[][] {{24, 0}, {56, 16}},
            "_ZTV7Diamond", new long[][] {{24, 0}, {72, 16}, {104, 32}});
        var names = Map.of("_ZTV6Single", "Single", "_ZTV8Multiple", "Multiple", "_ZTV11VirtualBase", "VirtualBase",
            "_ZTV11VirtualLeft", "VirtualLeft", "_ZTV12VirtualRight", "VirtualRight", "_ZTV7Diamond", "Diamond");
        var snapshots = new LinkedHashMap<Long, Snapshot>();
        long delta = currentProgram.getImageBase().getOffset() - GhidraImageBase.originalImageBase(currentProgram);
        for (var value : tables) {
            monitor.checkCancelled();
            var table = value.getAsJsonObject();
            String mangled = table.get("name").getAsString(), name = names.get(mangled);
            if (name == null) throw new AssertionError("unexpected compiler table " + mangled);
            var candidates = new ArrayList<Long>();
            var symbols = currentProgram.getSymbolTable().getSymbols(name);
            while (symbols.hasNext()) {
                var symbol = symbols.next();
                if (symbol.getSymbolType() == SymbolType.CLASS && symbol.getName().equals(name)) candidates.add(symbol.getID());
            }
            if (candidates.size() != 1) throw new AssertionError("ambiguous fixture class " + name + ": " + candidates);
            var address = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(table.get("address").getAsLong() + delta);
            var symbol = currentProgram.getSymbolTable().createLabel(address, "fixture_table_" + name, SourceType.USER_DEFINED);
            var points = new ArrayList<AddressPoint>();
            for (long[] point : geometry.get(mangled)) points.add(new AddressPoint((int) point[0], point[1], "source-built fixture object geometry"));
            var request = new Request(symbol.getID(), candidates.getFirst(), mangled, name, table.get("size").getAsInt(),
                points, "independently compiled fixture table identity");
            GhidraVtableBindings.save(currentProgram, request, monitor);
            var before = GhidraVtableBindings.read(currentProgram, symbol.getID(), monitor, this::println);
            if (before.status() != Status.VALID) throw new AssertionError("fixture table rejected");
            snapshots.put(symbol.getID(), before.snapshot());
            if (saveOnly) continue;
            // Patch a function pointer, not the offset-to-top, to require a byte-witness rejection.
            var at = address.add(points.getFirst().tableOffset());
            byte old = currentProgram.getMemory().getByte(at);
            currentProgram.getMemory().setByte(at, (byte) (old ^ 1));
            if (GhidraVtableBindings.read(currentProgram, symbol.getID(), monitor, this::println).status() != Status.REJECTED) {
                throw new AssertionError("patched imported table accepted");
            }
            currentProgram.getMemory().setByte(at, old);
            if (!before.equals(GhidraVtableBindings.read(currentProgram, symbol.getID(), monitor, this::println))) {
                throw new AssertionError("restored imported table differs");
            }
        }
        if (!saveOnly) currentProgram.setImageBase(currentProgram.getImageBase().add(0x200000), true);
        for (var entry : snapshots.entrySet()) {
            var after = GhidraVtableBindings.read(currentProgram, entry.getKey(), monitor, this::println);
            if (after.status() != Status.VALID || !after.snapshot().equals(entry.getValue())) throw new AssertionError("rebased snapshot changed");
        }
        Files.writeString(Path.of(getScriptArgs()[1]), new GsonBuilder().setPrettyPrinting().create().toJson(
            Map.of("status", "PASS_IMPORTED_VTABLE_BINDINGS", "snapshots", List.copyOf(snapshots.values()))) + "\n");
        println("vtable-bindings-imported=PASS tables=" + snapshots.size());
    }
}
