package ghidradwarfforge.dwarf;

import java.io.ByteArrayOutputStream;
import java.nio.ByteOrder;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

import ghidradwarfforge.dwarf.DwarfLocationExpression.AddressOperation;
import ghidradwarfforge.dwarf.DwarfLocationExpression.Expression;
import ghidradwarfforge.dwarf.DwarfLocationExpression.GenericOperation;
import ghidradwarfforge.dwarf.DwarfLocationExpression.Operation;
import ghidradwarfforge.locations.VariableStorageModel.LocationRange;
import ghidradwarfforge.locations.VariableStorageModel.VariableLocation;

/** Deterministic DWARF 5 location lists using absolute start/end entries. */
public final class Dwarf5LocationLists {
    private static final int DW_LLE_END_OF_LIST = 0x00;
    private static final int DW_LLE_START_END = 0x07;
    private static final int DW_OP_ADDR = 0x03;
    public record PlannedRange(LocationRange range, Expression expression) {
        public PlannedRange {
            Objects.requireNonNull(range);
            Objects.requireNonNull(expression);
        }
    }

    private record PlannedList(VariableLocation variable, List<PlannedRange> ranges) {
    }

    /** Owns the bytes and the exact plans that produced them. */
    public static final class Result {
        private final byte[] section;
        private final Map<VariableLocation, Long> offsets;
        private final Map<VariableLocation, List<PlannedRange>> plans;

        private Result(byte[] section, Map<VariableLocation, Long> offsets,
                Map<VariableLocation, List<PlannedRange>> plans) {
            this.section = section;
            this.offsets = Map.copyOf(offsets);
            this.plans = Map.copyOf(plans);
        }

        public byte[] section() {
            return section.clone();
        }

        public Map<VariableLocation, Long> offsets() {
            return offsets;
        }

        public Map<VariableLocation, List<PlannedRange>> plans() {
            return plans;
        }

        public boolean empty() {
            return section.length == 0;
        }
    }

    private Dwarf5LocationLists() {
    }

    public static Result build(List<VariableLocation> variables, int addressBytes,
            ByteOrder order) {
        return build(variables, addressBytes, order, () -> false);
    }

    public static Result build(List<VariableLocation> variables, int addressBytes,
            ByteOrder order, BooleanSupplier cancelled) {
        Objects.requireNonNull(variables);
        Objects.requireNonNull(order);
        Objects.requireNonNull(cancelled);
        checkCancelled(cancelled);
        if (addressBytes != 4 && addressBytes != 8) {
            throw new IllegalArgumentException("unsupported address size " + addressBytes);
        }
        List<PlannedList> listed = new java.util.ArrayList<>();
        for (VariableLocation variable : variables) {
            checkCancelled(cancelled);
            PlannedList planned = plan(variable, cancelled);
            if (planned != null) listed.add(planned);
        }
        if (listed.isEmpty()) {
            return new Result(new byte[0], Map.of(), Map.of());
        }

        ByteArrayOutputStream lists = new ByteArrayOutputStream();
        long unitOffset = 12;
        Map<VariableLocation, Long> offsets = new LinkedHashMap<>();
        Map<VariableLocation, List<PlannedRange>> plans = new LinkedHashMap<>();
        for (PlannedList list : listed) {
            checkCancelled(cancelled);
            offsets.put(list.variable(), Math.addExact(unitOffset, lists.size()));
            plans.put(list.variable(), list.ranges());
            writeList(lists, list, addressBytes, order, cancelled);
        }

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        writeUnsigned(body, 5, 2, order);
        body.write(addressBytes);
        body.write(0);
        writeUnsigned(body, 0, 4, order);
        body.writeBytes(lists.toByteArray());

        ByteArrayOutputStream section = new ByteArrayOutputStream();
        writeUnsigned(section, body.size(), 4, order);
        section.writeBytes(body.toByteArray());
        checkCancelled(cancelled);
        return new Result(section.toByteArray(), offsets, plans);
    }

    private static PlannedList plan(VariableLocation variable, BooleanSupplier cancelled) {
        if (variable.locations().size() <= 1) {
            return null;
        }
        java.util.ArrayList<PlannedRange> ranges = new java.util.ArrayList<>();
        for (LocationRange range : variable.locations()) {
            checkCancelled(cancelled);
            if (!range.storage().available()) {
                continue;
            }
            VariableLocation oneRange = new VariableLocation(variable.functionName(),
                variable.functionAddress(), variable.name(), variable.kind(),
                variable.byteSize(), List.of(range));
            if (!(DwarfLocationExpression.planStable(oneRange) instanceof Expression expression)) {
                return null;
            }
            ranges.add(new PlannedRange(range, expression));
        }
        return ranges.isEmpty() ? null : new PlannedList(variable, List.copyOf(ranges));
    }

    private static void writeList(ByteArrayOutputStream output,
            PlannedList list, int addressBytes, ByteOrder order, BooleanSupplier cancelled) {
        for (PlannedRange planned : list.ranges()) {
            checkCancelled(cancelled);
            byte[] expression = encodeExpression(planned.expression(), addressBytes, order, cancelled);
            output.write(DW_LLE_START_END);
            writeUnsigned(output, planned.range().start(), addressBytes, order);
            writeUnsigned(output, planned.range().end(), addressBytes, order);
            writeUleb(output, expression.length);
            output.writeBytes(expression);
        }
        output.write(DW_LLE_END_OF_LIST);
    }

    private static byte[] encodeExpression(Expression expression, int addressBytes,
            ByteOrder order, BooleanSupplier cancelled) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        for (Operation operation : expression.operations()) {
            checkCancelled(cancelled);
            if (operation instanceof AddressOperation address) {
                output.write(DW_OP_ADDR);
                writeUnsigned(output, address.address(), addressBytes, order);
                continue;
            }
            if (!(operation instanceof GenericOperation generic)) {
                throw new IllegalArgumentException("unsupported location-list operation");
            }
            output.write(generic.opcode());
            switch (generic.opcode()) {
                case DwarfLocationExpression.DW_OP_DEREF -> {
                    // Target-address-sized memory dereference has no operands.
                }
                case DwarfLocationExpression.DW_OP_REGX, DwarfLocationExpression.DW_OP_PIECE -> writeUleb(output,
                    generic.operand1());
                case DwarfLocationExpression.DW_OP_BREGX -> {
                    writeUleb(output, generic.operand1());
                    writeSleb(output, generic.operand2());
                }
                case DwarfLocationExpression.DW_OP_BIT_PIECE -> {
                    writeUleb(output, generic.operand1());
                    writeUleb(output, generic.operand2());
                }
                default -> throw new IllegalArgumentException(
                    "unsupported generic location-list opcode 0x" +
                        Integer.toHexString(generic.opcode()));
            }
        }
        return output.toByteArray();
    }

    private static void writeUleb(ByteArrayOutputStream output, long value) {
        if (value < 0) {
            throw new IllegalArgumentException("ULEB128 value must be nonnegative");
        }
        do {
            int next = (int) (value & 0x7f);
            value >>>= 7;
            output.write(value == 0 ? next : next | 0x80);
        } while (value != 0);
    }

    private static void writeSleb(ByteArrayOutputStream output, long value) {
        boolean more;
        do {
            int next = (int) (value & 0x7f);
            value >>= 7;
            boolean sign = (next & 0x40) != 0;
            more = !((value == 0 && !sign) || (value == -1 && sign));
            output.write(more ? next | 0x80 : next);
        } while (more);
    }

    private static void writeUnsigned(ByteArrayOutputStream output, long value,
            int width, ByteOrder order) {
        for (int index = 0; index < width; index++) {
            int shift = order == ByteOrder.LITTLE_ENDIAN ? index * 8 :
                (width - index - 1) * 8;
            output.write((int) (value >>> shift) & 0xff);
        }
    }

    private static void checkCancelled(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) {
            throw new CancellationException("location-list planning cancelled");
        }
    }
}
