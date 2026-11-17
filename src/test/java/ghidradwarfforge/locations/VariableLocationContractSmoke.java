package ghidradwarfforge.locations;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Random;

import ghidradwarfforge.dwarf.DwarfLocationExpression;
import ghidradwarfforge.dwarf.DwarfLocationExpression.AddressOperation;
import ghidradwarfforge.dwarf.DwarfLocationExpression.Expression;
import ghidradwarfforge.dwarf.DwarfLocationExpression.GenericOperation;
import ghidradwarfforge.dwarf.DwarfLocationExpression.Omitted;
import ghidradwarfforge.locations.VariableStorageModel.*;

/** Location model boundaries and omission contracts; no inferred register or frame facts. */
final class VariableLocationContractSmoke {
    private static final Evidence EVIDENCE = new Evidence(Confidence.USER_DEFINED, "saved analyst storage");
    private static final TargetRegisterMap REGISTERS = TargetRegisterMap.forTarget("x86_64");
    private static final RegisterStorage REGISTER = (RegisterStorage) REGISTERS.register("RAX", 0, 32);
    private static final UnavailableStorage UNKNOWN = new UnavailableStorage(OmissionReason.UNKNOWN_LIFETIME, "no proven lifetime");
    private static int checks;

    static void check() {
        lifetimeIntervals();
        pieceCompleteness();
        identityAndOwnership();
        missingEvidence();
        System.out.println("variable-location-contracts=PASS checks=" + checks);
    }

    private static VariableLocation variable(String function, long address, String name, VariableKind kind,
            long bytes, List<LocationRange> ranges) {
        return new VariableLocation(function, address, name, kind, bytes, ranges);
    }

    private static VariableLocation location(long bytes, Storage storage) {
        return variable("function", 100, "value", VariableKind.LOCAL, bytes,
            List.of(new LocationRange(100, 110, storage, EVIDENCE)));
    }

    private static void lifetimeIntervals() {
        List<Storage> states = List.of(REGISTER, UNKNOWN, REGISTERS.registerRelative("RSP", -16),
            new IndirectMemoryStorage(new MemoryStorage(0x4000)));
        for (int seed = 0; seed < 32; seed++) {
            var random = new Random(seed);
            var ranges = new ArrayList<LocationRange>();
            var expected = new Storage[128];
            int cursor = 0;
            for (int index = 0; index < 12; index++) {
                cursor += random.nextInt(3);
                int end = cursor + 1 + random.nextInt(4);
                Storage storage = states.get(index % states.size());
                ranges.add(new LocationRange(100 + cursor, 100 + end, storage, EVIDENCE));
                Arrays.fill(expected, cursor, end, storage);
                cursor = end;
            }
            Collections.shuffle(ranges, random);
            var value = variable("function", 100, "value", VariableKind.LOCAL, 4, ranges);
            for (int pc = 0; pc < expected.length; pc++) {
                long address = 100 + pc;
                var hits = value.locations().stream().filter(range -> range.start() <= address && address < range.end()).toList();
                require(hits.size() == (expected[pc] == null ? 0 : 1), "sorting changed half-open lifetime coverage");
                if (!hits.isEmpty()) require(hits.getFirst().storage().equals(expected[pc]) &&
                    hits.getFirst().evidence().equals(EVIDENCE), "sorting reassigned storage or analyst evidence");
            }
            require(value.hasDefensibleLocation() && value.changesLocation(), "mixed lifetime flags lost");
            require(DwarfLocationExpression.planStable(value) instanceof Omitted,
                "changing lifetime became one stable debugger expression");
        }
        // Adjacent half-open ranges are legal, even at the largest representable endpoint.
        var adjacent = variable("last", Long.MAX_VALUE - 4, "value", VariableKind.LOCAL, 4,
            List.of(new LocationRange(Long.MAX_VALUE - 2, Long.MAX_VALUE, REGISTER, EVIDENCE),
                new LocationRange(Long.MAX_VALUE - 4, Long.MAX_VALUE - 2, REGISTER, EVIDENCE)));
        require(adjacent.hasDefensibleLocation() && !adjacent.changesLocation(), "adjacent identical storage changed meaning");
        require(DwarfLocationExpression.planStable(adjacent) instanceof Expression, "valid stable endpoint was lost");
        for (long[] bounds : new long[][] {{-1, 1}, {100, 100}, {101, 100}}) {
            rejects(() -> new LocationRange(bounds[0], bounds[1], REGISTER, EVIDENCE), "invalid half-open interval");
        }
        for (long[] overlap : new long[][] {{100, 101}, {100, 110}, {101, 109}, {109, 120}}) {
            rejects(() -> variable("f", 100, "x", VariableKind.LOCAL, 4,
                List.of(new LocationRange(100, 110, REGISTER, EVIDENCE),
                    new LocationRange(overlap[0], overlap[1], UNKNOWN, EVIDENCE))), "overlapping lifetimes");
        }
    }

    private static void pieceCompleteness() {
        for (int bits : new int[] {1, 7, 8, 31, 32, 63}) {
            var first = REGISTERS.register("RAX", 0, bits);
            var second = REGISTERS.register("RDX", 0, 64 - bits);
            var pieces = new CompositeStorage(List.of(new Piece(first, bits), new Piece(second, 64 - bits)));
            require(pieces.totalBitSize() == 64 && DwarfLocationExpression.planStable(location(8, pieces)) instanceof Expression,
                "complete register pieces lost their variable");
            rejects(() -> location(7, pieces), "pieces exceed object width");
            rejects(() -> location(9, pieces), "pieces omit object bits");
        }
        for (int described : new int[] {31, 33}) {
            var mismatched = new CompositeStorage(List.of(new Piece(REGISTER, described),
                new Piece(REGISTERS.register("RDX", 0, 64 - described), 64 - described)));
            require(DwarfLocationExpression.planStable(location(8, mismatched)) instanceof Omitted,
                "piece width mismatch acquired a debugger location");
        }
        var complete = new CompositeStorage(List.of(new Piece(REGISTER, 32)));
        for (Storage rejected : Arrays.asList(null, UNKNOWN, complete)) {
            rejects(() -> new Piece(rejected, 32), "absent, unknown or nested piece");
        }
        for (int bits : new int[] {0, -1, Integer.MIN_VALUE}) {
            rejects(() -> new Piece(REGISTER, bits), "nonpositive piece width");
            rejects(() -> new RegisterStorage(REGISTER.register(), 0, bits), "nonpositive register width");
        }
        rejects(() -> new CompositeStorage(null), "missing pieces");
        rejects(() -> new CompositeStorage(List.of()), "empty pieces");
        for (Storage unresolved : List.of(new StackStorage(-16), REGISTER, UNKNOWN, complete,
                new IndirectMemoryStorage(new MemoryStorage(0x4000)))) {
            rejects(() -> new IndirectMemoryStorage(unresolved), "pointer carrier must be resolved memory");
        }
        require(DwarfLocationExpression.planStable(location(24, new IndirectMemoryStorage(new MemoryStorage(0x4000))))
            .equals(new Expression(List.of(new AddressOperation(0x4000), new GenericOperation(0x06, 0, 0)))),
            "absolute indirect carrier lost its dereference");
        require(DwarfLocationExpression.planStable(location(4, new StackStorage(-16))) instanceof Omitted,
            "raw Ghidra stack offset became a frame-relative debugger location");
        for (OmissionReason reason : OmissionReason.values()) {
            var omitted = location(4, new UnavailableStorage(reason, "analyst diagnostic " + reason));
            require(!omitted.hasDefensibleLocation() && !omitted.changesLocation(), "unavailable lifetime flags changed");
            require(DwarfLocationExpression.planStable(omitted).equals(new Omitted(reason, "analyst diagnostic " + reason)),
                "omission reason or diagnostic was replaced");
        }
        try {
            location(Long.MAX_VALUE / 8 + 1, new MemoryStorage(0x4000));
            throw new AssertionError("overflowing variable bit width was accepted");
        }
        catch (ArithmeticException expected) { checks++; }
    }

    private static void identityAndOwnership() {
        var ranges = new ArrayList<>(List.of(new LocationRange(100, 110, REGISTER, EVIDENCE)));
        var local = variable("function", 100, "value", VariableKind.LOCAL, 4, ranges);
        var parameter = variable("function", 100, "value", VariableKind.PARAMETER, 4, ranges);
        var another = variable("same spelling", 200, "value", VariableKind.LOCAL, 4, ranges);
        var inputs = new ArrayList<>(List.of(another, local, parameter));
        var model = new VariableStorageModel(inputs);
        ranges.clear();
        inputs.clear();
        require(model.variables().equals(List.of(parameter, local, another)) && local.locations().size() == 1,
            "caller mutation changed admitted locations or canonical identities");
        immutable(() -> model.variables().clear());
        immutable(() -> local.locations().clear());
        var pieces = new ArrayList<>(List.of(new Piece(REGISTER, 32)));
        var storage = new CompositeStorage(pieces);
        pieces.clear();
        require(storage.totalBitSize() == 32, "caller mutation changed composite width");
        immutable(() -> storage.pieces().clear());
        var alias = variable("renamed function", 100, "value", VariableKind.LOCAL, 4, local.locations());
        rejects(() -> new VariableStorageModel(List.of(local, alias)), "same identity with a different function spelling");
        require(new VariableStorageModel(List.of()).variables().isEmpty(), "empty inventory fabricated variables");
    }

    private static void missingEvidence() {
        for (String absent : Arrays.asList(null, "", " \t")) {
            rejects(() -> new Evidence(Confidence.USER_DEFINED, absent), "missing evidence source");
            rejects(() -> new UnavailableStorage(OmissionReason.UNKNOWN_LIFETIME, absent), "missing omission explanation");
            rejects(() -> variable(absent, 100, "x", VariableKind.LOCAL, 4, location(4, REGISTER).locations()), "missing function name");
            rejects(() -> variable("f", 100, absent, VariableKind.LOCAL, 4, location(4, REGISTER).locations()), "missing variable name");
        }
        rejects(() -> new Evidence(null, "analyst"), "missing confidence");
        rejects(() -> new UnavailableStorage(null, "not available"), "missing omission reason");
        rejects(() -> new LocationRange(100, 110, null, EVIDENCE), "missing storage");
        rejects(() -> new LocationRange(100, 110, REGISTER, null), "missing evidence");
        rejects(() -> new MemoryStorage(-1), "negative memory address");
        rejects(() -> new RegisterStorage(REGISTER.register(), -1, 32), "negative register offset");
        rejects(() -> new RegisterRelativeStorage(null, -16), "missing frame register");
        rejects(() -> variable("f", -1, "x", VariableKind.LOCAL, 4, location(4, REGISTER).locations()), "negative function address");
        rejects(() -> variable("f", 100, "x", null, 4, location(4, REGISTER).locations()), "missing variable kind");
        rejects(() -> variable("f", 100, "x", VariableKind.LOCAL, 0, location(4, REGISTER).locations()), "empty variable");
        rejects(() -> variable("f", 100, "x", VariableKind.LOCAL, 4, null), "missing lifetimes");
        rejects(() -> variable("f", 100, "x", VariableKind.LOCAL, 4, List.of()), "empty lifetimes");
        rejects(() -> new VariableStorageModel(null), "missing variable inventory");
    }

    private static void require(boolean value, String message) {
        checks++;
        if (!value) throw new AssertionError(message);
    }

    private static void rejects(Runnable action, String context) {
        try { action.run(); }
        catch (IllegalArgumentException expected) { checks++; return; }
        throw new AssertionError("invalid location contract accepted: " + context);
    }

    private static void immutable(Runnable action) {
        try { action.run(); }
        catch (UnsupportedOperationException expected) { checks++; return; }
        throw new AssertionError("admitted variable location is mutable");
    }
}
