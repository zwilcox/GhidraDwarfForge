package ghidradwarfforge.unwind;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import ghidradwarfforge.dwarf.DwarfDebugFrame;
import ghidradwarfforge.unwind.CallFramePlan.*;

/** Decode complete CFI state independently, including long jumps and signed expressions. */
public final class CallFrameEncodingBoundarySmoke {
    private static int checks;

    private CallFrameEncodingBoundarySmoke() { }

    public static void main(String[] args) {
        long[] offsets = {Long.MIN_VALUE, -8193, -65, -64, -1, 0, 63, 64, 127, 128, 8192, Long.MAX_VALUE};
        for (int width : new int[] {4, 8}) {
            for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                long[] bases = width == 4 ? new long[] {0, 0x1000} : new long[] {0x1000, Long.MAX_VALUE - 32};
                for (long base : bases) {
                    for (long offset : offsets) {
                        exercise(width, order, base, offset);
                    }
                }
            }
        }
        System.out.println("call-frame-encoding-boundaries=PASS checks=" + checks);
    }

    private static Map<Integer, Rule> rules(long offset, boolean alternate) {
        return Map.of(0, alternate ? new SameValue() : new Undefined(),
            127, new AtCfaOffset(offset), 128, new CfaValue(offset),
            4095, new InRegister(alternate ? 127 : 128));
    }

    private static void exercise(int width, ByteOrder order, long base, long offset) {
        Map<Integer, Rule> initial = Map.of(0, new Undefined(), 127, new SameValue(),
            128, new CfaValue(offset), 4095, new AtCfaOffset(offset));
        long[] positions = width == 4 ? new long[] {0, 1, 256, 65536} :
            new long[] {0, 0xffff_ffffL, 0x1_ffff_ffffL, 0x2_0000_0000L};
        var rows = new ArrayList<Row>();
        for (int i = 0; i < positions.length; i++) {
            rows.add(new Row(base + positions[i], new Cfa(i % 2 == 0 ? 0 : 4095, offset),
                rules(offset, i % 2 != 0)));
        }
        var frame = new Frame(base, positions[positions.length - 1] + 8, rows);
        var plan = new CallFramePlan(width, order, 4095, initial.keySet(), initial, List.of(frame));
        byte[] bytes = DwarfDebugFrame.build(plan, () -> false);
        check(Arrays.equals(bytes, DwarfDebugFrame.build(plan, () -> false)), "deterministic frame bytes");
        ByteBuffer input = ByteBuffer.wrap(bytes).order(order);
        int cieEnd = end(input);
        check(input.getInt() == -1 && input.get() == 4 && input.get() == 0, "CIE identity/version/augmentation");
        check(Byte.toUnsignedInt(input.get()) == width && input.get() == 0, "CIE target widths");
        check(leb(input, false) == 1 && leb(input, true) == 1, "CIE alignment factors");
        check(leb(input, false) == 4095, "return register must retain extended number");
        var initialState = new TreeMap<Integer, Rule>();
        while (input.position() < cieEnd) {
            int opcode = Byte.toUnsignedInt(input.get());
            if (opcode != 0) rule(input, opcode, initialState);
        }
        check(input.position() == cieEnd && initialState.equals(initial), "CIE rules must retain signed values");
        int frameEnd = end(input);
        check(input.getInt() == 0, "FDE CIE reference");
        check(address(input, width) == frame.address() && address(input, width) == frame.size(),
            "FDE address and extent must not be narrowed");
        long pc = frame.address();
        Cfa cfa = null;
        var current = new TreeMap<>(initialState);
        var decoded = new ArrayList<Row>();
        int advances = 0;
        int absoluteJumps = 0;
        while (input.position() < frameEnd) {
            int opcode = Byte.toUnsignedInt(input.get());
            if (opcode == 0) continue;
            if (opcode == 1 || opcode == 4) {
                check(cfa != null, "frame row must define a CFA before advancing");
                decoded.add(new Row(pc, cfa, current));
                if (opcode == 1) {
                    pc = address(input, width);
                    absoluteJumps++;
                }
                else {
                    pc += Integer.toUnsignedLong(input.getInt());
                    advances++;
                }
            }
            else if (opcode == 0x12) {
                cfa = new Cfa(Math.toIntExact(leb(input, false)), leb(input, true));
            }
            else {
                rule(input, opcode, current);
            }
        }
        check(cfa != null && input.position() == frameEnd && frameEnd == bytes.length,
            "complete frame record boundaries");
        decoded.add(new Row(pc, cfa, current));
        check(decoded.equals(rows), "decoded frame states differ from the explicit plan");
        check(width == 4 ? absoluteJumps == 0 && advances == 3 : absoluteJumps == 1 && advances == 2,
            "wide row gaps require set_loc without narrowing");
        for (int i = 0; i < rows.size(); i++) {
            long start = rows.get(i).address() - base;
            long stop = i + 1 < rows.size() ? rows.get(i + 1).address() - base : frame.size();
            for (long point : new long[] {start, stop - 1}) {
                Row found = null;
                for (Row candidate : decoded) {
                    if (candidate.address() - base <= point) found = candidate;
                }
                check(found != null && found.cfa().equals(rows.get(i).cfa()) &&
                    found.rules().equals(rows.get(i).rules()), "frame state changed before its instruction boundary");
            }
        }
    }

    private static void rule(ByteBuffer input, int opcode, Map<Integer, Rule> state) {
        int register = Math.toIntExact(leb(input, false));
        Rule value = switch (opcode) {
            case 7 -> new Undefined();
            case 8 -> new SameValue();
            case 9 -> new InRegister(Math.toIntExact(leb(input, false)));
            case 0x11 -> new AtCfaOffset(leb(input, true));
            case 0x16 -> {
                int length = Math.toIntExact(leb(input, false));
                int limit = Math.addExact(input.position(), length);
                int operation = Byte.toUnsignedInt(input.get());
                long offset;
                if (operation == 0x23) {
                    offset = leb(input, false);
                    check(offset >= 0, "positive CFA expression became negative");
                }
                else {
                    check(operation == 0x11, "unexpected CFA expression operation");
                    offset = leb(input, true);
                    check(offset < 0 && input.get() == 0x22, "negative CFA expression must add signed displacement");
                }
                check(input.position() == limit, "CFA expression length does not match its operations");
                yield new CfaValue(offset);
            }
            default -> throw new AssertionError("unexpected CFI rule opcode " + opcode);
        };
        state.put(register, value);
    }

    private static int end(ByteBuffer input) {
        long length = Integer.toUnsignedLong(input.getInt());
        long end = input.position() + length;
        check(length != 0xffff_ffffL && end <= input.limit(), "invalid DWARF32 record length");
        return Math.toIntExact(end);
    }

    private static long address(ByteBuffer input, int width) {
        return width == 4 ? Integer.toUnsignedLong(input.getInt()) : input.getLong();
    }

    private static long leb(ByteBuffer input, boolean signed) {
        BigInteger value = BigInteger.ZERO;
        int bits = 0;
        int octet;
        do {
            check(bits < 70, "overlong LEB operand");
            octet = Byte.toUnsignedInt(input.get());
            value = value.add(BigInteger.valueOf(octet & 0x7f).shiftLeft(bits));
            bits += 7;
        } while ((octet & 0x80) != 0);
        if (signed && (octet & 0x40) != 0) value = value.subtract(BigInteger.ONE.shiftLeft(bits));
        return value.longValueExact();
    }

    private static void check(boolean valid, String message) {
        checks++;
        if (!valid) throw new AssertionError(message);
    }
}
