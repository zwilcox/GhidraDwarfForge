package ghidradwarfforge;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import ghidradwarfforge.GhidraVariableStorage.StackDepthInterval;
import ghidradwarfforge.GhidraVariableStorage.StackDepthProfile;
import ghidradwarfforge.GhidraVariableStorage.StorageInterval;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.OmissionReason;
import ghidradwarfforge.locations.VariableStorageModel.RegisterRelativeStorage;
import ghidradwarfforge.locations.VariableStorageModel.StackStorage;
import ghidradwarfforge.locations.VariableStorageModel.UnavailableStorage;

/** Coordinate-stage arithmetic and unavailable gaps; not a new recovered ABI claim. */
public final class StackCoordinateProjectionSmoke {
    private static int checks;
    private record Target(String name, String pointer, int number, int bits) { }
    private static final List<Target> TARGETS = List.of(
        new Target("x86", "ESP", 4, 32), new Target("x86_64", "RSP", 7, 64),
        new Target("arm", "sp", 13, 32), new Target("aarch64", "sp", 31, 64),
        new Target("mips", "sp", 29, 32), new Target("mipsel", "sp", 29, 32),
        new Target("mips64", "sp", 29, 64), new Target("mips64el", "sp", 29, 64));

    public static void main(String[] args) {
        check();
    }

    static int check() {
        checks = 0;
        long[] slots = {Long.MIN_VALUE, Long.MIN_VALUE + 1, Long.MIN_VALUE + 4096,
            Integer.MIN_VALUE, -8192, -1, 0, 1, 4096, Integer.MAX_VALUE,
            Long.MAX_VALUE - 4096, Long.MAX_VALUE - 1, Long.MAX_VALUE};
        int[] depths = {-1048576, -4096, -128, -1, 0, 1, 127, 4096, 1048576};
        for (Target target : TARGETS) {
            var map = TargetRegisterMap.forTarget(target.name());
            for (long slot : slots) {
                for (int depth : depths) {
                    coordinates(target, map, slot, depth);
                }
            }
            missingPointer(target, map);
        }
        invalidIntervals();
        System.out.println("stack-coordinate-projection=PASS checks=" + checks);
        return checks;
    }

    private static void coordinates(Target target, TargetRegisterMap map, long slot, int depth) {
        var rows = new ArrayList<>(List.of(new StackDepthInterval(0x1000, 0x1004, depth, true),
            new StackDepthInterval(0x1004, 0x1008, depth, false),
            new StackDepthInterval(0x1010, 0x1018, depth, true)));
        var profile = new StackDepthProfile(target.pointer(), rows);
        var snapshot = List.copyOf(rows);
        rows.clear();
        require(profile.intervals().equals(snapshot), "profile retained mutable caller list");
        // Use unbounded effective-address arithmetic, rather than Java's signed
        // subtraction, as the independent oracle for displacement and overflow.
        BigInteger entryPointer = BigInteger.ONE.shiftLeft(target.bits() - 1);
        BigInteger objectAddress = entryPointer.add(BigInteger.valueOf(slot));
        BigInteger currentPointer = entryPointer.add(BigInteger.valueOf(depth));
        BigInteger displacement = objectAddress.subtract(currentPointer);
        boolean fits = displacement.compareTo(BigInteger.valueOf(Long.MIN_VALUE)) >= 0 &&
            displacement.compareTo(BigInteger.valueOf(Long.MAX_VALUE)) <= 0;
        if (!fits) {
            expect(ArithmeticException.class,
                () -> GhidraVariableStorage.stackIntervals(profile, new StackStorage(slot), map));
        }
        else {
            var projected = GhidraVariableStorage.stackIntervals(profile, new StackStorage(slot), map);
            require(projected.size() == snapshot.size(), "lost unknown interval or filled instruction gap");
            for (int index = 0; index < projected.size(); index++) {
                var actual = projected.get(index);
                var input = snapshot.get(index);
                require(actual.start() == input.start() && actual.end() == input.end(), "changed address range");
                if (input.known()) {
                    require(actual.storage() instanceof RegisterRelativeStorage, "known offset omitted");
                    var relative = (RegisterRelativeStorage) actual.storage();
                    require(relative.register().dwarfNumber() == target.number(), "wrong stack register");
                    require(currentPointer.add(BigInteger.valueOf(relative.byteOffset())).equals(objectAddress),
                        "debugger effective address disagrees with entry-relative object");
                }
                else {
                    require(actual.storage() instanceof UnavailableStorage omitted &&
                        omitted.reason() == OmissionReason.UNKNOWN_LIFETIME, "unknown depth acquired location");
                }
            }
            require(projected.equals(GhidraVariableStorage.stackIntervals(profile, new StackStorage(slot), map)),
                "projection is not deterministic");
            expect(UnsupportedOperationException.class, () -> projected.add(projected.getFirst()));
        }
        // An unknown interval has no displacement to overflow. It must remain
        // unavailable even for the same coordinates that a known row rejects.
        var unknown = new StackDepthProfile(target.pointer(), List.of(new StackDepthInterval(0, 1, depth, false)));
        var unavailable = GhidraVariableStorage.stackIntervals(unknown, new StackStorage(slot), map);
        require(unavailable.size() == 1 && unavailable.getFirst().storage() instanceof UnavailableStorage omitted &&
            omitted.reason() == OmissionReason.UNKNOWN_LIFETIME, "unknown row used unproven arithmetic");
        require(profile.intervals().equals(snapshot), "projection changed input evidence");
    }

    private static void missingPointer(Target target, TargetRegisterMap map) {
        var rows = List.of(new StackDepthInterval(0, 1, 0, true));
        for (String blank : List.of("", "  ")) {
            require(GhidraVariableStorage.stackIntervals(new StackDepthProfile(blank, rows),
                new StackStorage(0), map).isEmpty(), "missing stack register acquired location");
        }
        require(GhidraVariableStorage.stackIntervals(new StackDepthProfile(target.pointer(), List.of()),
            new StackStorage(0), map).isEmpty(), "empty evidence acquired a range");
        var unresolved = GhidraVariableStorage.stackIntervals(new StackDepthProfile("unmapped_stack_pointer", rows),
            new StackStorage(0), map);
        require(unresolved.size() == 1 && unresolved.getFirst().storage() instanceof UnavailableStorage omitted &&
            omitted.reason() == OmissionReason.UNMAPPED_REGISTER, "unmapped pointer substituted a known register");
    }

    private static void invalidIntervals() {
        for (long[] range : List.of(new long[] {-1, 1}, new long[] {0, 0}, new long[] {1, 0},
                new long[] {Long.MAX_VALUE, Long.MIN_VALUE})) {
            expect(IllegalArgumentException.class, () -> new StackDepthInterval(range[0], range[1], 0, true));
            expect(IllegalArgumentException.class, () -> new StorageInterval(range[0], range[1], new StackStorage(0)));
        }
        expect(IllegalArgumentException.class, () -> new StorageInterval(0, 1, null));
        expect(IllegalArgumentException.class, () -> new StackDepthProfile(null, List.of()));
        expect(IllegalArgumentException.class, () -> new StackDepthProfile("RSP", null));
    }

    private static void expect(Class<? extends RuntimeException> kind, Runnable action) {
        try {
            action.run();
        }
        catch (RuntimeException failure) {
            require(kind.isInstance(failure), "unexpected failure: " + failure);
            return;
        }
        throw new AssertionError("missing " + kind.getSimpleName());
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
