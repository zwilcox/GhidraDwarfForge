package ghidradwarfforge;

import java.util.ArrayList;
import java.util.List;
import ghidradwarfforge.GhidraVariableStorage.StorageInterval;
import ghidradwarfforge.locations.VariableStorageModel.DwarfRegister;
import ghidradwarfforge.locations.VariableStorageModel.OmissionReason;
import ghidradwarfforge.locations.VariableStorageModel.RegisterRelativeStorage;
import ghidradwarfforge.locations.VariableStorageModel.RegisterStorage;
import ghidradwarfforge.locations.VariableStorageModel.Storage;
import ghidradwarfforge.locations.VariableStorageModel.UnavailableStorage;

/** Finite-domain oracle for refining locations without inventing lifetime coverage. */
public final class StorageRefinementSmoke {
    private static int checks;
    private static final Storage REGISTER = new RegisterStorage(new DwarfRegister("RDI", 5), 0, 32);
    private static final Storage STACK = new RegisterRelativeStorage(new DwarfRegister("RSP", 7), -24);
    private static final Storage ORIGINAL_UNKNOWN = new UnavailableStorage(OmissionReason.UNKNOWN_LIFETIME, "original gap");
    private static final Storage EXTRA_UNKNOWN = new UnavailableStorage(OmissionReason.REGISTER_MODIFIED, "new evidence unavailable");
    private static final int[] ORIGINAL_EDGES = {2, 4, 6, 8, 10};
    private static final int[] EXTRA_EDGES = {1, 3, 7, 9, 11};

    public static void main(String[] args) {
        check();
    }

    static int check() {
        checks = 0;
        int cases = 0;
        for (long base : new long[] {0, 0x1_0000_0000L, Long.MAX_VALUE - 16}) {
            // Each cell is absent, unavailable, register, or stack-relative.
            // Both maps are valid ordered, nonoverlapping intervals. Distinct
            // boundaries exercise partial intersections and clipping at both ends.
            var originals = new ArrayList<List<StorageInterval>>();
            var extras = new ArrayList<List<StorageInterval>>();
            for (int encoding = 0; encoding < 256; encoding++) {
                originals.add(intervals(base, ORIGINAL_EDGES, encoding, ORIGINAL_UNKNOWN));
                extras.add(intervals(base, EXTRA_EDGES, encoding, EXTRA_UNKNOWN));
            }
            for (int first = 0; first < originals.size(); first++) {
                for (int second = 0; second < extras.size(); second++) {
                    var original = originals.get(first);
                    var extra = extras.get(second);
                    var actual = StackValueFlow.extendUnavailable(original, extra);
                    String context = "base=" + base + "/original=" + first + "/extra=" + second;
                    long end = -1;
                    Storage last = null;
                    for (var interval : actual) {
                        require(interval.start() >= end && interval.end() > interval.start(), "overlap/order " + context);
                        require(interval.start() >= base + 2 && interval.end() <= base + 10, "invented extent " + context);
                        require(interval.start() != end || !interval.storage().equals(last), "uncollapsed adjacency " + context);
                        end = interval.end();
                        last = interval.storage();
                    }
                    for (int point = 0; point <= 12; point++) {
                        // Direct cell selection is independent of the production
                        // interval sweep, cursor advancement, and append/coalescing.
                        Storage before = cell(point, ORIGINAL_EDGES, first, ORIGINAL_UNKNOWN);
                        Storage addition = cell(point, EXTRA_EDGES, second, EXTRA_UNKNOWN);
                        Storage expected = before == null ? null : before.available() ? before :
                            addition != null && addition.available() ? addition : before;
                        Storage observed = null;
                        for (var interval : actual) {
                            if (interval.start() <= base + point && base + point < interval.end()) {
                                require(observed == null, "multiple locations " + context);
                                observed = interval.storage();
                            }
                        }
                        require(java.util.Objects.equals(expected, observed), "incorrect location at " + point + " " + context);
                    }
                    require(actual.equals(StackValueFlow.extendUnavailable(original, extra)), "nondeterministic " + context);
                    cases++;
                }
            }
        }
        require(cases == 196608, "incomplete finite-domain matrix");
        System.out.println("storage-refinement=PASS cases=" + cases + " checks=" + checks +
            " oracle=pointwise address-domains=3");
        return checks;
    }

    private static Storage cell(int point, int[] edges, int encoding, Storage unknown) {
        for (int index = 0; index < 4; index++) {
            if (point >= edges[index] && point < edges[index + 1]) {
                return value((encoding >>> (index * 2)) & 3, unknown);
            }
        }
        return null;
    }

    private static Storage value(int code, Storage unknown) {
        return switch (code) {
            case 0 -> null;
            case 1 -> unknown;
            case 2 -> REGISTER;
            case 3 -> STACK;
            default -> throw new AssertionError("invalid fixture code");
        };
    }

    private static List<StorageInterval> intervals(long base, int[] edges, int encoding, Storage unknown) {
        var result = new ArrayList<StorageInterval>();
        for (int index = 0; index < 4;) {
            int code = (encoding >>> (index * 2)) & 3;
            int limit = index + 1;
            while (limit < 4 && ((encoding >>> (limit * 2)) & 3) == code) limit++;
            if (code != 0) result.add(new StorageInterval(base + edges[index], base + edges[limit], value(code, unknown)));
            index = limit;
        }
        return List.copyOf(result);
    }

    private static void require(boolean value, String message) {
        checks++;
        if (!value) throw new AssertionError(message);
    }
}
