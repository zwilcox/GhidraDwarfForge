package ghidradwarfforge.dwarf;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Map;

import ghidradwarfforge.targets.CxxAbiProfile;
import ghidradwarfforge.types.InheritanceModel.VirtualBase;

/** Byte vectors and a small independent DWARF stack evaluator; GDB is tested separately. */
public final class DwarfInheritanceExpressionSmoke {
    private static int checks;

    public static void main(String[] args) {
        int[] slots = {0, 127, 128, 16383, 16384, 65535};
        String[] bytes = {"1000", "107f", "108001", "10ff7f", "10808001", "10ffff03"};
        for (int i = 0; i < slots.length; i++) {
            byte[] expression = DwarfInheritanceExpression.virtualSlot(slots[i]);
            check(Arrays.equals(expression, java.util.HexFormat.of().parseHex(bytes[i])), "slot byte vector");
            check(evaluate(expression, 0, Map.of(), false) == slots[i], "slot index, not byte displacement");
        }
        for (int invalid : new int[] {-1, Integer.MIN_VALUE, 65536, Integer.MAX_VALUE}) {
            rejects(() -> DwarfInheritanceExpression.virtualSlot(invalid));
        }
        for (CxxAbiProfile abi : new CxxAbiProfile[] {
                CxxAbiProfile.ITANIUM_X86_64, CxxAbiProfile.ITANIUM_AARCH64}) {
            check(Arrays.equals(DwarfInheritanceExpression.virtualBase(abi, new VirtualBase(0, -24), 8),
                java.util.HexFormat.of().parseHex("12061168220622")), "ordinary virtual-base byte vector");
            check(Arrays.equals(DwarfInheritanceExpression.virtualBase(abi, new VirtualBase(128, -72), 136),
                java.util.HexFormat.of().parseHex("238001120611b87f220622")), "multi-byte displacements");
            // Exercise sign-extension boundaries, a ten-byte SLEB, and large ULEBs.
            // The memory oracle fixes the desired base address independently of encoding.
            for (long vptr : new long[] {0, 8, 128, 16384, 1L << 56}) {
                for (long slot : new long[] {-24, -64, -72, -8192, -8200, Long.MIN_VALUE}) {
                    for (long displacement : new long[] {-32, 0, 96}) {
                        long object = 0x1000, table = 0x2000;
                        var memory = Map.of(object + vptr, table, table + slot, displacement);
                        byte[] expression = DwarfInheritanceExpression.virtualBase(abi,
                            new VirtualBase(vptr, slot), vptr + 8);
                        check(evaluate(expression, object, memory, true) == object + vptr + displacement,
                            "virtual base is relative to the selected subobject");
                    }
                }
            }
            rejects(() -> DwarfInheritanceExpression.virtualBase(abi, new VirtualBase(0, -24), 7));
            rejects(() -> DwarfInheritanceExpression.virtualBase(abi, new VirtualBase(8, -24), 15));
            rejects(() -> DwarfInheritanceExpression.virtualBase(abi, new VirtualBase(1, -24), 16));
            rejects(() -> DwarfInheritanceExpression.virtualBase(abi, new VirtualBase(0, -16), 8));
            rejects(() -> DwarfInheritanceExpression.virtualBase(abi, new VirtualBase(0, -25), 8));
        }
        rejects(() -> DwarfInheritanceExpression.virtualBase(CxxAbiProfile.UNSPECIFIED,
            new VirtualBase(0, -24), 8));
        System.out.println("inheritance-expression=PASS checks=" + checks);
    }

    private static long evaluate(byte[] expression, long object, Map<Long, Long> memory, boolean member) {
        var stack = new ArrayDeque<Long>();
        if (member) stack.push(object);
        var input = ByteBuffer.wrap(expression);
        while (input.hasRemaining()) {
            switch (Byte.toUnsignedInt(input.get())) {
                case 0x06 -> {
                    Long value = memory.get(stack.pop());
                    check(value != null, "expression dereferenced an unexpected address");
                    stack.push(value);
                }
                case 0x10 -> stack.push(leb(input, false));
                case 0x11 -> stack.push(leb(input, true));
                case 0x12 -> stack.push(stack.peek());
                case 0x22 -> stack.push(stack.pop() + stack.pop());
                case 0x23 -> stack.push(stack.pop() + leb(input, false));
                default -> throw new AssertionError("unexpected or value-only DWARF opcode");
            }
        }
        check(stack.size() == 1, "member expression must leave exactly one address");
        return stack.pop();
    }

    private static long leb(ByteBuffer input, boolean signed) {
        BigInteger value = BigInteger.ZERO;
        int width = 0, octet;
        do {
            octet = Byte.toUnsignedInt(input.get());
            value = value.or(BigInteger.valueOf(octet % 128).shiftLeft(width));
            width += 7;
            check(width <= 70, "bounded 64-bit LEB");
        } while (octet >= 128);
        if (signed && (octet & 64) != 0) value = value.subtract(BigInteger.ONE.shiftLeft(width));
        return value.longValueExact();
    }

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }

    private static void rejects(Runnable action) {
        try {
            action.run();
            throw new AssertionError("accepted invalid inheritance expression");
        }
        catch (IllegalArgumentException expected) {
            checks++;
        }
    }
}
