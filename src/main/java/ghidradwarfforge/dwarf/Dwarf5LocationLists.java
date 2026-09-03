package ghidradwarfforge.dwarf;

import java.io.ByteArrayOutputStream;
import java.nio.ByteOrder;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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
    private record PlannedRange(LocationRange range, Expression expression) {
    }

    private record PlannedList(VariableLocation variable, List<PlannedRange> ranges) {
    }

    public record Result(byte[] section, Map<VariableLocation, Long> offsets) {
        public Result {
            section = section.clone();
            offsets = Map.copyOf(offsets);
        }

        @Override
        public byte[] section() {
            return section.clone();
        }

        public boolean empty() {
            return section.length == 0;
        }
    }

    private Dwarf5LocationLists() {
    }

    public static Result build(List<VariableLocation> variables, int addressBytes,
            ByteOrder order) {
        if (addressBytes != 4 && addressBytes != 8) {
            throw new IllegalArgumentException("unsupported address size " + addressBytes);
        }
        List<PlannedList> listed = variables.stream()
            .map(Dwarf5LocationLists::plan)
            .filter(java.util.Objects::nonNull)
            .toList();
        if (listed.isEmpty()) {
            return new Result(new byte[0], Map.of());
        }

        ByteArrayOutputStream lists = new ByteArrayOutputStream();
        long unitOffset = 12;
        Map<VariableLocation, Long> offsets = new LinkedHashMap<>();
        for (PlannedList list : listed) {
            offsets.put(list.variable(), Math.addExact(unitOffset, lists.size()));
            writeList(lists, list, addressBytes, order);
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
        return new Result(section.toByteArray(), offsets);
    }

    private static PlannedList plan(VariableLocation variable) {
        if (!variable.hasDefensibleLocation() ||
                (variable.locations().size() <= 1 && !variable.changesLocation())) {
            return null;
        }
        java.util.ArrayList<PlannedRange> ranges = new java.util.ArrayList<>();
        for (LocationRange range : variable.locations()) {
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
            PlannedList list, int addressBytes, ByteOrder order) {
        for (PlannedRange planned : list.ranges()) {
            byte[] expression = encodeExpression(planned.expression(), addressBytes, order);
            output.write(DW_LLE_START_END);
            writeUnsigned(output, planned.range().start(), addressBytes, order);
            writeUnsigned(output, planned.range().end(), addressBytes, order);
            writeUleb(output, expression.length);
            output.writeBytes(expression);
        }
        output.write(DW_LLE_END_OF_LIST);
    }

    private static byte[] encodeExpression(Expression expression, int addressBytes,
            ByteOrder order) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        for (Operation operation : expression.operations()) {
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
                case DwarfLocationExpression.DW_OP_REGX -> writeUleb(output,
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
}
