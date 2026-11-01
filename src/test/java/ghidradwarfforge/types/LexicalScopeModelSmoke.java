package ghidradwarfforge.types;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;

import ghidradwarfforge.dwarf.Dwarf5RangeLists;
import ghidradwarfforge.locations.VariableStorageModel;
import ghidradwarfforge.locations.VariableStorageModel.*;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;

/** Independent range decoding and ownership/location-negative controls. */
public final class LexicalScopeModelSmoke {
    private static int checks;

    public static void main(String[] args) {
        var body = List.of(new FunctionRange(0x1000, 0x80), new FunctionRange(0x1100, 0x80));
        var inner = List.of(new FunctionRange(0x1020, 0x20), new FunctionRange(0x1120, 0x20));
        var blocks = List.of(new LexicalScopeModel.Block("inner", "outer", inner),
            new LexicalScopeModel.Block("outer", "", body));
        var locals = List.of(new LexicalScopeModel.Local("one", "outer", "value"),
            new LexicalScopeModel.Local("two", "inner", "value"));
        var scope = new LexicalScopeModel(0x1000, body, blocks, locals, "analyst record");
        check(scope.blocks().getFirst().id().equals("outer"), "parent precedes child");
        var storage = new RegisterStorage(new DwarfRegister("fixture", 0), 0, 32);
        var evidence = new Evidence(Confidence.USER_DEFINED, "independent physical proof");
        var location = new VariableLocation("f", 0x1000, "two", VariableKind.LOCAL, 4,
            List.of(new LocationRange(0x1028, 0x1130, storage, evidence)));
        var clipped = scope.restrict(location);
        check(clipped.locations().stream().map(r -> List.of(r.start(), r.end(), r.storage().available() ? 1L : 0L))
            .toList().equals(List.of(List.of(0x1020L, 0x1028L, 0L), List.of(0x1028L, 0x1040L, 1L),
                List.of(0x1120L, 0x1130L, 1L), List.of(0x1130L, 0x1140L, 0L))), "exact intersection and unavailable holes");
        check(scope.restrict(clipped).equals(clipped), "idempotent policy cloning");
        var absent = new VariableLocation("f", 0x1000, "two", VariableKind.LOCAL, 4,
            List.of(new LocationRange(0x1000, 0x1010, storage, evidence)));
        check(scope.restrict(absent).locations().size() == 2 &&
            scope.restrict(absent).locations().stream().noneMatch(r -> r.storage().available()), "scope never creates storage");
        rejects(() -> scope.restrict(new VariableLocation("wrong", 0x2000, "two", VariableKind.LOCAL, 4,
            location.locations())), "foreign function");
        rejects(() -> new LexicalScopeModel(0x1000, body, List.of(
            new LexicalScopeModel.Block("a", "b", body), new LexicalScopeModel.Block("b", "a", body)), List.of(), "record"), "cycle");
        rejects(() -> new LexicalScopeModel(0x1000, body, List.of(
            new LexicalScopeModel.Block("a", "missing", body)), List.of(), "record"), "missing parent");
        rejects(() -> new LexicalScopeModel(0x1000, body, List.of(
            new LexicalScopeModel.Block("a", "", body), new LexicalScopeModel.Block("b", "", inner)), List.of(), "record"), "overlapping sibling");
        rejects(() -> new LexicalScopeModel(0x1000, body, List.of(
            new LexicalScopeModel.Block("a", "", List.of(new FunctionRange(0x1070, 0x30)))), List.of(), "record"), "body hole");
        rejects(() -> new LexicalScopeModel(0x1000, body, blocks, List.of(
            new LexicalScopeModel.Local("one", "inner", "value"), new LexicalScopeModel.Local("two", "inner", "value")), "record"), "same-block duplicate name");
        rejects(() -> new LexicalScopeModel(0x1000, body, blocks, List.of(
            new LexicalScopeModel.Local("one", "missing", "value")), "record"), "missing local owner");
        var function = new FunctionSymbol("f", 0x1000, body);
        for (int width : new int[] { 4, 8 }) {
            for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                var encoded = Dwarf5RangeLists.build(List.of(function), List.of(scope), width, order);
                var data = ByteBuffer.wrap(encoded.section()).order(order);
                check(Integer.toUnsignedLong(data.getInt()) == data.remaining(), "unit length");
                check(data.getShort() == 5 && data.get() == width && data.get() == 0 && data.getInt() == 0, "header");
                read(data, encoded.compilationUnitOffset(), body, width);
                read(data, encoded.functionOffsets().get(function), body, width);
                read(data, encoded.lexicalOffsets().get(new LexicalScopeModel.Key(0x1000, "outer")), body, width);
                read(data, encoded.lexicalOffsets().get(new LexicalScopeModel.Key(0x1000, "inner")), inner, width);
                check(data.position() == data.limit(), "all range bytes accounted for");
            }
        }
        rejects(() -> Dwarf5RangeLists.build(List.of(new FunctionSymbol("f", 0x1000, 0x80)), List.of(scope), 8,
            ByteOrder.LITTLE_ENDIAN), "different exported body");
        var tooWide = new FunctionSymbol("wide", 0x100000000L,
            List.of(new FunctionRange(0x100000000L, 4), new FunctionRange(0x100000010L, 4)));
        rejects(() -> Dwarf5RangeLists.build(List.of(tooWide), 4, ByteOrder.LITTLE_ENDIAN), "32-bit truncation");
        System.out.println("lexical-scope-model=PASS checks=" + checks);
    }

    private static void read(ByteBuffer data, long offset, List<FunctionRange> ranges, int width) {
        data.position(Math.toIntExact(offset));
        for (var range : ranges) {
            check(data.get() == 6, "start/end opcode");
            long start = width == 4 ? Integer.toUnsignedLong(data.getInt()) : data.getLong();
            long end = width == 4 ? Integer.toUnsignedLong(data.getInt()) : data.getLong();
            check(start == range.address() && end == range.endExclusive(), "independent endpoints");
        }
        check(data.get() == 0, "list terminator");
    }

    private static void rejects(Runnable operation, String label) {
        try {
            operation.run();
        }
        catch (IllegalArgumentException expected) {
            checks++;
            return;
        }
        throw new AssertionError("accepted " + label);
    }

    private static void check(boolean condition, String label) {
        if (!condition) throw new AssertionError(label);
        checks++;
    }
}
