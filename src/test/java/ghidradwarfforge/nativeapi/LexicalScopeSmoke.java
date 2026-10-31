package ghidradwarfforge.nativeapi;

import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import ghidradwarfforge.dwarf.Dwarf5RangeLists;
import ghidradwarfforge.locations.VariableStorageModel;
import ghidradwarfforge.locations.VariableStorageModel.*;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.types.LexicalScopeModel;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.TypeGraph;

/** Isolated producer coverage; physical values are tested by the real Ghidra fixture. */
public final class LexicalScopeSmoke {
    public static void main(String[] args) throws Exception {
        if (args.length != 6) throw new IllegalArgumentException("consumer producer input output entry size");
        long entry = Long.decode(args[4]);
        long size = Long.decode(args[5]);
        if (size < 48) throw new AssertionError("native fixture too short");
        var body = List.of(new FunctionRange(entry, size));
        var inner = List.of(new FunctionRange(entry + 8, 8), new FunctionRange(entry + 32, 8));
        var scopes = new LexicalScopeModel(entry, body, List.of(
            new LexicalScopeModel.Block("inner", "outer", inner),
            new LexicalScopeModel.Block("outer", "", List.of(new FunctionRange(entry + 2, size - 4)))), List.of(
                new LexicalScopeModel.Local("outer_saved", "outer", "value"),
                new LexicalScopeModel.Local("inner_saved", "inner", "value")), "explicit fixture scope");
        var type = new TypeGraph.TypeRef("int");
        var graph = new TypeGraph(List.of(new TypeGraph.BaseType("int", "int", 4, TypeGraph.BaseEncoding.SIGNED)));
        var signature = new ProgramTypeModel.FunctionSignature("scoped", entry, type, List.of(), List.of(
            new ProgramTypeModel.LocalVariable("outer_saved", 4, type, 0, true, "USER_DEFINED"),
            new ProgramTypeModel.LocalVariable("inner_saved", 4, type, 0, true, "USER_DEFINED")), false, false, "default", "USER_DEFINED");
        var storage = new RegisterStorage(new DwarfRegister("fixture_register", 0), 0, 32);
        var evidence = new Evidence(Confidence.USER_DEFINED, "isolated serialization fixture");
        var locations = new VariableStorageModel(List.of(
            new VariableLocation("scoped", entry, "outer_saved", VariableKind.LOCAL, 4,
                List.of(new LocationRange(entry, entry + size, storage, evidence))),
            new VariableLocation("scoped", entry, "inner_saved", VariableKind.LOCAL, 4,
                List.of(new LocationRange(entry + 10, entry + 36, storage, evidence)))));
        var model = new ProgramTypeModel(graph, List.of(signature), List.of(), locations, List.of(), List.of(), List.of(scopes));
        var clipped = model.variableStorage().variables().stream().filter(v -> v.name().equals("inner_saved")).findFirst().orElseThrow();
        if (!clipped.locations().stream().map(r -> List.of(r.start() - entry, r.end() - entry, r.storage().available() ? 1L : 0L)).toList()
                .equals(List.of(List.of(8L, 10L, 0L), List.of(10L, 16L, 1L), List.of(32L, 36L, 1L), List.of(36L, 40L, 0L)))) {
            throw new AssertionError("scope widened or lost unavailable gaps");
        }
        var function = new FunctionSymbol("scoped", entry, size);
        for (int width : new int[] { 4, 8 }) {
            for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                var ranges = Dwarf5RangeLists.build(List.of(function), List.of(scopes), width, order);
                if (ranges.empty() || !ranges.functionOffsets().isEmpty() || ranges.lexicalOffsets().size() != 1 ||
                        ranges.lexicalOffsets().get(new LexicalScopeModel.Key(entry, "inner")) != 12 + (1 + width * 2 + 1)) {
                    throw new AssertionError("lexical ranges missing from independent range table");
                }
            }
        }
        Path input = Path.of(args[2]);
        byte[] original = Files.readAllBytes(input);
        var exporter = new MinimalDwarfSidecarExporter();
        exporter.export(input, Path.of(args[3]), Path.of(args[0]), Path.of(args[1]), List.of(function), null, model);
        if (!java.util.Arrays.equals(original, Files.readAllBytes(input))) throw new AssertionError("input changed");
        System.out.println("lexical-scope-native=PASS");
    }
}
