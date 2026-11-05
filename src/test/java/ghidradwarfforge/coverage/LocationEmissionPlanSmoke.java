package ghidradwarfforge.coverage;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

import ghidradwarfforge.dwarf.Dwarf5LocationLists;
import ghidradwarfforge.dwarf.DwarfLocationExpression;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.*;

/** Raw location-list decoding and negative controls for retained emission plans. */
public final class LocationEmissionPlanSmoke {
    private static final Evidence EVIDENCE = new Evidence(Confidence.ANALYSIS, "fixture evidence");
    private static int checks;

    public static void main(String[] args) {
        // Uses only the pre-existing build/section API for parent/candidate comparisons.
        if (args.length == 1 && args[0].equals("--dump")) {
            for (int width : new int[] {4, 8}) {
                for (var order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                    System.out.println(width + " " + order + " " + HexFormat.of().formatHex(
                        Dwarf5LocationLists.build(fixtures(), width, order).section()));
                }
            }
            return;
        }
        List<VariableLocation> variables = fixtures();
        for (int width : new int[] {4, 8}) {
            for (var order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                var result = Dwarf5LocationLists.build(variables, width, order);
                require(result.offsets().size() == 3 && result.plans().size() == 3,
                    "only three full-value lists survive");
                assertList(result, variables.get(0), width, order,
                    new long[][] {{0x1000, 0x1010, 0}, {0x1010, 0x1020, 1}});
                assertList(result, variables.get(1), width, order,
                    new long[][] {{0x1000, 0x1008, 0}, {0x1018, 0x1020, 1}});
                assertList(result, variables.get(2), width, order,
                    new long[][] {{0x1000, 0x1008, 0}, {0x1018, 0x1020, 0}});
                for (int i = 3; i < variables.size(); i++) {
                    require(!result.plans().containsKey(variables.get(i)),
                        "no phantom list for rejected or stable variable " + i);
                }
                for (int i : new int[] {3, 4, 5, 7, 8}) {
                    require(DwarfLocationExpression.planStable(variables.get(i)) instanceof
                        DwarfLocationExpression.Omitted, "rejected list has no valid stable fallback " + i);
                }
                require(DwarfLocationExpression.planStable(variables.get(6)) instanceof
                    DwarfLocationExpression.Expression, "single full location uses an expression, not a list");
                require(variables.get(3).hasDefensibleLocation() && variables.get(4).hasDefensibleLocation(),
                    "extraction-level availability is weaker than an emitted full-value location");
                byte[] changed = result.section();
                changed[0] ^= 0x7f;
                require(!Arrays.equals(changed, result.section()), "section snapshot is immutable");
                immutable(() -> result.plans().clear());
                immutable(() -> result.plans().get(variables.getFirst()).clear());
                immutable(() -> result.offsets().clear());
                var empty = Dwarf5LocationLists.build(variables.subList(3, variables.size()), width, order);
                require(empty.empty() && empty.offsets().isEmpty() && empty.plans().isEmpty(),
                    "empty section has no fabricated evidence");
            }
        }
        AtomicInteger ticks = new AtomicInteger();
        Dwarf5LocationLists.build(variables, 8, ByteOrder.LITTLE_ENDIAN, () -> {
            ticks.incrementAndGet();
            return false;
        });
        for (int stop : new int[] {1, 4, 20, ticks.get() - 2, ticks.get()}) {
            AtomicInteger count = new AtomicInteger();
            try {
                Dwarf5LocationLists.build(variables, 8, ByteOrder.LITTLE_ENDIAN,
                    () -> count.incrementAndGet() == stop);
                throw new AssertionError("cancelled plan returned partial success");
            }
            catch (CancellationException expected) {
                require(count.get() == stop, "prompt cancellation at checkpoint " + stop);
            }
        }
        System.out.println("location emission plan smoke passed: " + checks + " checks across four encodings");
    }

    private static void assertList(Dwarf5LocationLists.Result result, VariableLocation variable,
            int width, ByteOrder order, long[][] expected) {
        ByteBuffer bytes = ByteBuffer.wrap(result.section()).order(order);
        require(bytes.getInt() == bytes.limit() - 4 && bytes.getShort() == 5 &&
            Byte.toUnsignedInt(bytes.get()) == width && bytes.get() == 0 && bytes.getInt() == 0,
            "DWARF5 location-list header");
        bytes.position(Math.toIntExact(result.offsets().get(variable)));
        var plans = result.plans().get(variable);
        require(plans.size() == expected.length, "plan count equals raw oracle");
        for (int i = 0; i < expected.length; i++) {
            long[] range = expected[i];
            require(bytes.get() == 7, "DW_LLE_start_end");
            long start = width == 8 ? bytes.getLong() : Integer.toUnsignedLong(bytes.getInt());
            long end = width == 8 ? bytes.getLong() : Integer.toUnsignedLong(bytes.getInt());
            require(start == range[0] && end == range[1], "raw exact half-open location interval");
            require(bytes.get() == 2 && Byte.toUnsignedInt(bytes.get()) == 0x90 &&
                bytes.get() == range[2], "raw full-register expression");
            require(plans.get(i).range().start() == start && plans.get(i).range().end() == end,
                "retained interval matches actual bytes");
            require(plans.get(i).expression().operations().equals(List.of(
                new DwarfLocationExpression.GenericOperation(0x90, range[2], 0))),
                "retained expression matches actual bytes");
        }
        require(bytes.get() == 0, "DW_LLE_end_of_list");
    }

    private static List<VariableLocation> fixtures() {
        var registers = TargetRegisterMap.forTarget("x86_64");
        Storage full = registers.register("RAX", 0, 64);
        Storage other = registers.register("RDX", 0, 64);
        Storage partial = registers.register("RDX", 0, 32);
        Storage unknown = new UnavailableStorage(OmissionReason.UNKNOWN_LIFETIME, "unproven interval");
        Storage badPiece = new CompositeStorage(List.of(new Piece(partial, 64)));
        return List.of(
            variable("moving", range(0x1000, 0x1010, full), range(0x1010, 0x1020, other)),
            variable("gap", range(0x1000, 0x1008, full), range(0x1008, 0x1018, unknown),
                range(0x1018, 0x1020, other)),
            variable("discontiguous", range(0x1000, 0x1008, full), range(0x1018, 0x1020, full)),
            variable("partial", range(0x1000, 0x1020, partial)),
            variable("mixedPartial", range(0x1000, 0x1010, full), range(0x1010, 0x1020, partial)),
            variable("badPiece", range(0x1000, 0x1010, full), range(0x1010, 0x1020, badPiece)),
            variable("stable", range(0x1000, 0x1020, full)),
            variable("unknown", range(0x1000, 0x1010, unknown), range(0x1010, 0x1020, unknown)),
            variable("rawStack", range(0x1000, 0x1010, new StackStorage(-4)),
                range(0x1010, 0x1020, new StackStorage(-12))));
    }

    private static VariableLocation variable(String name, LocationRange... ranges) {
        return new VariableLocation("function", 0x1000, name, VariableKind.LOCAL, 8, List.of(ranges));
    }

    private static LocationRange range(long start, long end, Storage storage) {
        return new LocationRange(start, end, storage, EVIDENCE);
    }

    private static void immutable(Runnable action) {
        try {
            action.run();
        }
        catch (UnsupportedOperationException expected) {
            checks++;
            return;
        }
        throw new AssertionError("mutable emission evidence");
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
