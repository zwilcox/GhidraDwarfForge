package ghidradwarfforge.locations;

import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidradwarfforge.locations.TargetRegisterMap.PairPiece;
import ghidradwarfforge.locations.TargetRegisterMap.RegisterSlice;
import ghidradwarfforge.locations.VariableStorageModel.OmissionReason;
import ghidradwarfforge.locations.VariableStorageModel.UnavailableStorage;

/** Admission and ownership of explicit register descriptions, not new target support. */
final class RegisterMapContractSmoke {
    private static int checks;
    private static final Map<String, Integer> NUMBERS = Map.of("lo", 0, "hi", 1);
    private static final PairPiece LOW = new PairPiece("lo", 0, 32);
    private static final PairPiece HIGH = new PairPiece("hi", 32, 32);

    static void check() {
        descriptorBounds();
        mapBounds();
        pairedDescriptions();
        sliceDescriptions();
        ownedSnapshots();
        System.out.println("register-map-contracts=PASS checks=" + checks);
    }

    private static void descriptorBounds() {
        for (String name : new String[] {null, "", " \t"}) {
            reject(() -> new PairPiece(name, 0, 32));
            reject(() -> new RegisterSlice(name, 64, 0, 32, 0));
        }
        for (int bad : new int[] {-1, Integer.MIN_VALUE}) {
            reject(() -> new PairPiece("lo", bad, 32));
            reject(() -> new RegisterSlice("lo", 64, bad, 32, 0));
            reject(() -> new RegisterSlice("lo", 64, 0, 32, bad));
        }
        for (int bad : new int[] {0, -1, Integer.MIN_VALUE}) {
            reject(() -> new PairPiece("lo", 0, bad));
            reject(() -> new RegisterSlice("lo", bad, 0, 32, 0));
            reject(() -> new RegisterSlice("lo", 64, 0, bad, 0));
        }
        // Physical and logical placement are independent. A slice may occupy
        // either physical half while describing either logical half.
        for (int byteOffset : new int[] {0, 4}) {
            for (int bitOffset : new int[] {0, 32}) {
                var slice = new RegisterSlice("lo", 64, byteOffset, 32, bitOffset);
                require(slice.parent().equals("lo") && slice.parentBits() == 64 &&
                    slice.byteOffset() == byteOffset && slice.bitSize() == 32 &&
                    slice.valueBitOffset() == bitOffset, "slice coordinates were conflated");
            }
        }
        for (int offset : new int[] {5, 8, Integer.MAX_VALUE}) {
            reject(() -> new RegisterSlice("lo", 64, offset, 32, 0));
        }
        for (int offset : new int[] {33, 64, Integer.MAX_VALUE}) {
            reject(() -> new RegisterSlice("lo", 64, 0, 32, offset));
        }
        reject(() -> new RegisterSlice("lo", 64, 0, 65, 0));
        reject(() -> new RegisterSlice("lo", 64, 0, Integer.MAX_VALUE, 1));
        var whole = new RegisterSlice("lo", 64, 0, 64, 0);
        require(whole.bitSize() == whole.parentBits(), "whole register slice rejected");
    }

    private static void mapBounds() {
        for (String bad : new String[] {null, "", " \t"}) {
            reject(() -> new TargetRegisterMap(bad, "explicit fixture", NUMBERS));
            reject(() -> new TargetRegisterMap("fixture", bad, NUMBERS));
        }
        reject(() -> new TargetRegisterMap("fixture", "explicit fixture", null));
        reject(() -> new TargetRegisterMap("fixture", "explicit fixture", Map.of()));
        reject(() -> new TargetRegisterMap("fixture", "explicit fixture", NUMBERS, null));
        reject(() -> new TargetRegisterMap("fixture", "explicit fixture", NUMBERS, Map.of(), null, null));
        for (String bad : new String[] {null, "", " \t"}) {
            var numbers = new HashMap<>(NUMBERS);
            numbers.put(bad, 2);
            reject(() -> new TargetRegisterMap("fixture", "explicit fixture", numbers));
        }
        for (Integer bad : new Integer[] {null, -1, Integer.MIN_VALUE}) {
            var numbers = new HashMap<>(NUMBERS);
            numbers.put("other", bad);
            reject(() -> new TargetRegisterMap("fixture", "explicit fixture", numbers));
        }
        // Different physical names may share a DWARF number (register aliases).
        var aliases = new TargetRegisterMap("fixture", "explicit alias", Map.of("lo", 0, "alias", 0));
        require(aliases.dwarfNumbers().equals(Map.of("lo", 0, "alias", 0)), "valid numeric alias rejected");
        for (String missing : new String[] {null, "", "absent"}) {
            for (var storage : List.of(aliases.register(missing, 0, 32), aliases.registerRelative(missing, -8))) {
                require(storage instanceof UnavailableStorage omitted &&
                    omitted.reason() == OmissionReason.UNMAPPED_REGISTER && !omitted.available() &&
                    omitted.diagnostic().contains(missing == null ? "<null>" : missing),
                    "unknown register acquired a fabricated location");
            }
        }
    }

    private static void pairedDescriptions() {
        for (String bad : new String[] {null, "", " \t"}) {
            var pairs = new HashMap<String, List<PairPiece>>();
            pairs.put(bad, List.of(LOW, HIGH));
            reject(() -> map(pairs, Map.of()));
        }
        var absent = new HashMap<String, List<PairPiece>>();
        absent.put("pair", null);
        reject(() -> map(absent, Map.of()));
        for (List<PairPiece> bad : List.of(List.<PairPiece>of(), List.of(LOW), List.of(LOW, HIGH, LOW),
                List.of(LOW, LOW), List.of(LOW, new PairPiece("lo", 32, 32)),
                List.of(LOW, new PairPiece("absent", 32, 32)),
                List.of(new PairPiece("absent", 0, 32), HIGH),
                List.of(new PairPiece("lo", 1, 31), HIGH),
                List.of(LOW, new PairPiece("hi", 24, 32)),
                List.of(LOW, new PairPiece("hi", 40, 32)))) {
            reject(() -> map(Map.of("pair", bad), Map.of()));
        }
        for (var order : List.of(List.of(LOW, HIGH), List.of(HIGH, LOW))) {
            var map = map(Map.of("pair", order), Map.of());
            require(map.registerPairs().get("pair").equals(order), "object-memory pair order was sorted away");
        }
    }

    private static void sliceDescriptions() {
        var slice = new RegisterSlice("lo", 64, 4, 32, 0);
        for (String bad : new String[] {null, "", " \t"}) {
            var slices = new HashMap<String, RegisterSlice>();
            slices.put(bad, slice);
            reject(() -> map(Map.of(), slices));
        }
        var absent = new HashMap<String, RegisterSlice>();
        absent.put("slice", null);
        reject(() -> map(Map.of(), absent));
        reject(() -> map(Map.of(), Map.of("slice", new RegisterSlice("absent", 64, 0, 32, 0))));
        require(map(Map.of(), Map.of("slice", slice)).registerSlices().get("slice").equals(slice),
            "logical slice lost physical coordinates");
    }

    private static void ownedSnapshots() {
        var numbers = new HashMap<>(NUMBERS);
        var pieces = new ArrayList<>(List.of(HIGH, LOW));
        var pairs = new HashMap<String, List<PairPiece>>();
        pairs.put("pair", pieces);
        var slice = new RegisterSlice("lo", 64, 4, 32, 0);
        var slices = new HashMap<>(Map.of("slice", slice));
        for (ByteOrder order : new ByteOrder[] {null, ByteOrder.BIG_ENDIAN, ByteOrder.LITTLE_ENDIAN}) {
            var map = new TargetRegisterMap("fixture", "explicit fixture", numbers, pairs, slices, order);
            require(map.registerStorageByteOrder() == order, "register storage order changed");
            immutable(() -> map.dwarfNumbers().put("new", 2));
            immutable(() -> map.registerPairs().clear());
            immutable(() -> map.registerPairs().get("pair").clear());
            immutable(() -> map.registerSlices().clear());
        }
        var map = new TargetRegisterMap("fixture", "explicit fixture", numbers, pairs, slices, ByteOrder.BIG_ENDIAN);
        numbers.clear(); pieces.clear(); pairs.clear(); slices.clear();
        require(map.dwarfNumbers().equals(NUMBERS) && map.registerPairs().equals(Map.of("pair", List.of(HIGH, LOW))) &&
            map.registerSlices().equals(Map.of("slice", slice)), "caller changed retained register descriptions");
        require(new ArrayList<>(map.dwarfNumbers().keySet()).equals(List.of("hi", "lo")),
            "register metadata order is nondeterministic");
    }

    private static TargetRegisterMap map(Map<String, List<PairPiece>> pairs, Map<String, RegisterSlice> slices) {
        return new TargetRegisterMap("fixture", "explicit fixture", NUMBERS, pairs, slices, null);
    }

    private static void reject(Runnable action) {
        try { action.run(); }
        catch (IllegalArgumentException expected) { checks++; return; }
        throw new AssertionError("invalid register description accepted");
    }

    private static void immutable(Runnable action) {
        try { action.run(); }
        catch (UnsupportedOperationException expected) { checks++; return; }
        throw new AssertionError("retained register description is mutable");
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
