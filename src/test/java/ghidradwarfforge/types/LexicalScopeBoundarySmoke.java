package ghidradwarfforge.types;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import ghidradwarfforge.locations.VariableStorageModel.*;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange;

/** Independent pointwise visibility oracle plus malformed saved-ownership controls. */
public final class LexicalScopeBoundarySmoke {
    private static int checks;
    private static final Evidence PROOF = new Evidence(Confidence.ANALYSIS, "independent register proof");
    private static final RegisterStorage REGISTER = new RegisterStorage(new DwarfRegister("fixture", 3), 0, 32);

    private LexicalScopeBoundarySmoke() { }

    public static void main(String[] args) { run(); }

    public static void run() {
        checks = 0;
        malformedOwnership();
        int cases = 0;
        for (long base : new long[] { 0x1000, 0x1_0000_0000L, Long.MAX_VALUE - 64 }) {
            for (int visible = 1; visible < 64; visible++) {
                var scope = new LexicalScopeModel(base, List.of(new FunctionRange(base, 6)),
                    List.of(new LexicalScopeModel.Block("block", "", visibility(base, visible))),
                    List.of(new LexicalScopeModel.Local("saved", "block", "value")), "analyst visibility");
                for (int physical = 0; physical < 64; physical++) {
                    var old = new ArrayList<LocationRange>();
                    for (var range : ranges(base, physical)) {
                        old.add(new LocationRange(range.address(), range.endExclusive(), REGISTER, PROOF));
                    }
                    // A proof entirely outside this scope must never become an
                    // in-scope location; VariableLocation requires a nonempty list.
                    if (old.isEmpty()) old.add(new LocationRange(base + 8, base + 9, REGISTER, PROOF));
                    var input = new VariableLocation("f", base, "saved", VariableKind.LOCAL, 4, old);
                    var actual = scope.restrict(input);
                    for (int point = -1; point <= 8; point++) {
                        LocationRange observed = null;
                        for (var range : actual.locations()) {
                            if (range.start() <= base + point && base + point < range.end()) {
                                require(observed == null, "overlapping restricted intervals");
                                observed = range;
                            }
                        }
                        boolean shown = point >= 0 && point < 6 && (visible & (1 << point)) != 0;
                        boolean proved = point >= 0 && point < 6 && (physical & (1 << point)) != 0;
                        require((observed != null) == shown, "scope visibility changed");
                        if (shown) {
                            require(observed.storage().available() == proved, "location fabricated or lost");
                            if (proved) require(observed.storage().equals(REGISTER) && observed.evidence().equals(PROOF),
                                "physical proof or provenance changed");
                            else require(observed.storage() instanceof UnavailableStorage unavailable
                                && unavailable.reason() == OmissionReason.UNKNOWN_LIFETIME,
                                "unproved visibility was not marked unavailable");
                        }
                    }
                    require(scope.restrict(actual).equals(actual), "restriction is not idempotent");
                    require(input.locations().equals(old), "restriction changed its input");
                    require(LexicalScopeModel.contains(scope.body(), scope.blocks().getFirst().ranges()),
                        "valid scope rejected by containment");
                    cases++;
                }
            }
        }
        require(cases == 12096, "incomplete visibility matrix");
        System.out.println("lexical-scope-boundaries=PASS cases=" + cases + " checks=" + checks);
    }

    private static List<FunctionRange> ranges(long base, int mask) {
        var result = new ArrayList<FunctionRange>();
        for (int bit = 0; bit < 6; bit++) {
            // Deliberately keep adjacent singleton intervals: production must
            // handle a continuous extent expressed as multiple ranges too.
            if ((mask & (1 << bit)) != 0) result.add(new FunctionRange(base + bit, 1));
        }
        return result;
    }

    private static List<FunctionRange> visibility(long base, int mask) {
        var result = new ArrayList<FunctionRange>();
        for (int bit = 0; bit < 6;) {
            if ((mask & (1 << bit)) == 0) { bit++; continue; }
            int start = bit++;
            while (bit < 6 && (mask & (1 << bit)) != 0) bit++;
            result.add(new FunctionRange(base + start, bit - start));
        }
        return result;
    }

    private static void malformedOwnership() {
        var body = List.of(new FunctionRange(10, 6));
        for (String missing : Arrays.asList(null, "", " \n")) {
            reject(() -> new LexicalScopeModel.Block(missing, "", body));
            reject(() -> new LexicalScopeModel.Local(missing, "", "value"));
            reject(() -> new LexicalScopeModel.Local("saved", "", missing));
            reject(() -> new LexicalScopeModel(10, body, List.of(), List.of(), missing));
        }
        reject(() -> new LexicalScopeModel.Block("block", null, body));
        reject(() -> new LexicalScopeModel.Local("saved", null, "value"));
        reject(() -> new LexicalScopeModel(10, body, null, List.of(), "saved"));
        reject(() -> new LexicalScopeModel(10, body, List.of(), null, "saved"));
        reject(() -> new LexicalScopeModel(-1, body, List.of(), List.of(), "saved"));
        reject(() -> new LexicalScopeModel(9, body, List.of(), List.of(), "saved"));
        reject(() -> new LexicalScopeModel(10, null, List.of(), List.of(), "saved"));
        reject(() -> new LexicalScopeModel(10, List.of(), List.of(), List.of(), "saved"));
        var block = new LexicalScopeModel.Block("block", "", body);
        reject(() -> new LexicalScopeModel(10, body, List.of(block, block), List.of(), "saved"));
        var local = new LexicalScopeModel.Local("saved", "block", "value");
        reject(() -> new LexicalScopeModel(10, body, List.of(block), List.of(local, local), "saved"));
        var scope = new LexicalScopeModel(10, body, List.of(block), List.of(local), "saved");
        var unrelated = new VariableLocation("other", 100, "unrecorded", VariableKind.LOCAL, 4,
            List.of(new LocationRange(100, 101, REGISTER, PROOF)));
        require(scope.restrict(unrelated) == unrelated, "unrecorded variable was rewritten");
        require(scope.local("unrecorded") == null, "invented local ownership");
        var root = new LexicalScopeModel(10, body, List.of(),
            List.of(new LexicalScopeModel.Local("saved", "", "value")), "saved");
        require(root.visibility(root.local("saved")).equals(body), "root local lost full-body visibility");
        require(!LexicalScopeModel.contains(List.of(new FunctionRange(10, 2), new FunctionRange(13, 3)),
            List.of(new FunctionRange(11, 4))), "containment bridged a hole");
    }

    private static void reject(Runnable operation) {
        try { operation.run(); }
        catch (IllegalArgumentException expected) { checks++; return; }
        throw new AssertionError("accepted malformed lexical ownership");
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
