package ghidradwarfforge.calls;

import java.io.ByteArrayOutputStream;
import java.nio.ByteOrder;
import java.util.Objects;

/**
 * Bounded integer actual-value expressions. Incoming values refer to the
 * caller's function-entry register, never the potentially clobbered current
 * register. Every intermediate carries the machine operation's byte width.
 * An unavailable value is represented by absence in the analysis, not here.
 */
public sealed interface CallValue {
    int bytes();
    int nodes();
    int depth();

    enum Op {
        ADD(0x22), SUBTRACT(0x1c), MULTIPLY(0x1e), AND(0x1a), OR(0x21), XOR(0x27),
        SHIFT_LEFT(0x24), SHIFT_RIGHT(0x25), EQUAL(0x29), NOT_EQUAL(0x2e);
        final int dwarf;
        Op(int dwarf) { this.dwarf = dwarf; }
    }

    record Literal(long value, int bytes) implements CallValue {
        public Literal { width(bytes); value &= mask(bytes); }
        public int nodes() { return 1; }
        public int depth() { return 1; }
    }
    record Incoming(int register, int bytes) implements CallValue {
        public Incoming {
            width(bytes);
            if (register < 0) throw new IllegalArgumentException("negative DWARF register");
        }
        public int nodes() { return 1; }
        public int depth() { return 1; }
    }
    record Slice(CallValue source, int lowBit, int bytes) implements CallValue {
        public Slice {
            width(bytes); Objects.requireNonNull(source);
            if (lowBit < 0 || lowBit > source.bytes() * 8 - bytes * 8) {
                throw new IllegalArgumentException("value slice exceeds its source");
            }
            bound(1 + source.nodes(), 1 + source.depth());
        }
        public int nodes() { return 1 + source.nodes(); }
        public int depth() { return 1 + source.depth(); }
    }
    record Extend(CallValue source, boolean signed, int bytes) implements CallValue {
        public Extend {
            width(bytes); Objects.requireNonNull(source);
            if (bytes < source.bytes()) throw new IllegalArgumentException("extension narrows value");
            bound(1 + source.nodes(), 1 + source.depth());
        }
        public int nodes() { return 1 + source.nodes(); }
        public int depth() { return 1 + source.depth(); }
    }
    record Binary(Op op, CallValue left, CallValue right, int bytes) implements CallValue {
        public Binary {
            width(bytes); Objects.requireNonNull(op); Objects.requireNonNull(left); Objects.requireNonNull(right);
            boolean comparison = op == Op.EQUAL || op == Op.NOT_EQUAL;
            boolean shift = op == Op.SHIFT_LEFT || op == Op.SHIFT_RIGHT;
            if ((!shift && left.bytes() != right.bytes()) || (comparison ? bytes != 1 : bytes != left.bytes())) {
                throw new IllegalArgumentException("inconsistent integer operation widths");
            }
            bound(1 + left.nodes() + right.nodes(), 1 + Math.max(left.depth(), right.depth()));
        }
        public int nodes() { return 1 + left.nodes() + right.nodes(); }
        public int depth() { return 1 + Math.max(left.depth(), right.depth()); }
    }
    record Select(CallValue condition, CallValue yes, CallValue no) implements CallValue {
        public Select {
            Objects.requireNonNull(condition); Objects.requireNonNull(yes); Objects.requireNonNull(no);
            if (condition.bytes() != 1 || yes.bytes() != no.bytes()) throw new IllegalArgumentException("invalid select widths");
            bound(1 + condition.nodes() + yes.nodes() + no.nodes(),
                1 + Math.max(condition.depth(), Math.max(yes.depth(), no.depth())));
        }
        public int bytes() { return yes.bytes(); }
        public int nodes() { return 1 + condition.nodes() + yes.nodes() + no.nodes(); }
        public int depth() { return 1 + Math.max(condition.depth(), Math.max(yes.depth(), no.depth())); }
    }

    static CallValue slice(CallValue source, int lowBit, int bytes) {
        var checked = new Slice(source, lowBit, bytes);
        if (lowBit == 0 && bytes == source.bytes()) return source;
        if (source instanceof Literal literal) return new Literal(literal.value() >>> lowBit, bytes);
        if (source instanceof Slice part) return slice(part.source(), part.lowBit() + lowBit, bytes);
        if (source instanceof Extend extended && lowBit + bytes * 8 <= extended.source().bytes() * 8) {
            return slice(extended.source(), lowBit, bytes);
        }
        if (source instanceof Binary binary && (binary.op() == Op.AND || binary.op() == Op.OR || binary.op() == Op.XOR)) {
            return binary(binary.op(), slice(binary.left(), lowBit, bytes), slice(binary.right(), lowBit, bytes), bytes);
        }
        return checked;
    }

    static CallValue extend(CallValue source, boolean signed, int bytes) {
        var checked = new Extend(source, signed, bytes);
        if (source.bytes() == bytes) return source;
        if (source instanceof Literal literal) {
            long value = literal.value();
            if (signed) value = signExtend(value, source.bytes());
            return new Literal(value, bytes);
        }
        return checked;
    }

    static CallValue binary(Op op, CallValue left, CallValue right, int bytes) {
        var checked = new Binary(op, left, right, bytes);
        if (left instanceof Literal a && right instanceof Literal b) {
            long result = switch (op) {
                case ADD -> a.value() + b.value();
                case SUBTRACT -> a.value() - b.value();
                case MULTIPLY -> a.value() * b.value();
                case AND -> a.value() & b.value();
                case OR -> a.value() | b.value();
                case XOR -> a.value() ^ b.value();
                case SHIFT_LEFT -> Long.compareUnsigned(b.value(), left.bytes() * 8L) >= 0 ? 0 : a.value() << b.value();
                case SHIFT_RIGHT -> Long.compareUnsigned(b.value(), left.bytes() * 8L) >= 0 ? 0 : a.value() >>> b.value();
                case EQUAL -> a.value() == b.value() ? 1 : 0;
                case NOT_EQUAL -> a.value() != b.value() ? 1 : 0;
            };
            return new Literal(result, bytes);
        }
        if (left.equals(right)) {
            if (op == Op.SUBTRACT || op == Op.XOR || op == Op.NOT_EQUAL) return new Literal(0, bytes);
            if (op == Op.EQUAL) return new Literal(1, bytes);
            if (op == Op.AND || op == Op.OR) return left;
        }
        if (right instanceof Literal literal) {
            if (literal.value() == 0 && (op == Op.AND || op == Op.MULTIPLY)) return new Literal(0, bytes);
            if (literal.value() == 0 && (op == Op.ADD || op == Op.SUBTRACT || op == Op.OR || op == Op.XOR ||
                    op == Op.SHIFT_LEFT || op == Op.SHIFT_RIGHT)) return left;
            if (literal.value() == 1 && op == Op.MULTIPLY) return left;
        }
        if (left instanceof Literal literal && literal.value() == 0) {
            if (op == Op.AND || op == Op.MULTIPLY) return new Literal(0, bytes);
            if (op == Op.ADD || op == Op.OR || op == Op.XOR) return right;
        }
        return checked;
    }

    static CallValue select(CallValue condition, CallValue yes, CallValue no) {
        var checked = new Select(condition, yes, no);
        if (yes.equals(no)) return yes;
        if (condition instanceof Literal literal) return literal.value() != 0 ? yes : no;
        return checked;
    }

    /** Emits an expression value, with no implicit dereference or stack_value. */
    default byte[] dwarf(int addressBytes, ByteOrder order) {
        if (addressBytes != 4 && addressBytes != 8) throw new IllegalArgumentException("unsupported DWARF stack width");
        Objects.requireNonNull(order);
        var out = new ByteArrayOutputStream();
        emit(this, addressBytes, order, out);
        if (out.size() > 4096) throw new IllegalArgumentException("call-value bytecode budget exceeded");
        return out.toByteArray();
    }

    private static void emit(CallValue value, int addressBytes, ByteOrder order, ByteArrayOutputStream out) {
        if (value.bytes() > addressBytes) throw new IllegalArgumentException("value exceeds DWARF stack width");
        if (value instanceof Literal literal) constant(out, literal.value());
        else if (value instanceof Incoming incoming) {
            var register = new ByteArrayOutputStream();
            register.write(0x90); uleb(register, incoming.register()); // DW_OP_regx
            out.write(0xa3); uleb(out, register.size()); out.writeBytes(register.toByteArray());
        }
        else if (value instanceof Slice slice) {
            emit(slice.source(), addressBytes, order, out);
            if (slice.lowBit() != 0) { constant(out, slice.lowBit()); out.write(0x25); }
        }
        else if (value instanceof Extend extended) {
            emit(extended.source(), addressBytes, order, out);
            if (extended.signed() && extended.source().bytes() < addressBytes) {
                long sign = 1L << (extended.source().bytes() * 8 - 1);
                constant(out, sign); out.write(0x27);
                constant(out, sign); out.write(0x1c);
            }
        }
        else if (value instanceof Binary binary) {
            if (binary.op() == Op.SHIFT_LEFT || binary.op() == Op.SHIFT_RIGHT) {
                // DWARF consumer shifts must not inherit Java/CPU masked shift
                // counts. The p-code result is zero when count >= operand bits.
                if (!(binary.right() instanceof Literal amount) ||
                        Long.compareUnsigned(amount.value(), binary.left().bytes() * 8L) >= 0) {
                    if (binary.right() instanceof Literal) { constant(out, 0); return; }
                    throw new IllegalArgumentException("nonconstant shift requires a separately bounded expression");
                }
            }
            emit(binary.left(), addressBytes, order, out);
            emit(binary.right(), addressBytes, order, out);
            out.write(binary.op().dwarf);
        }
        else if (value instanceof Select selected) {
            emit(selected.condition(), addressBytes, order, out);
            byte[] yes = selected.yes().dwarf(addressBytes, order);
            byte[] no = selected.no().dwarf(addressBytes, order);
            out.write(0x28); offset(out, no.length + 3, order); // DW_OP_bra
            out.writeBytes(no);
            out.write(0x2f); offset(out, yes.length, order); // DW_OP_skip
            out.writeBytes(yes);
            // Keep the join at an operation within the expression, including
            // when this select is the final full-width value. libdwarf's
            // branch-target validator rejects a target past the last operation.
            out.write(0x96); // DW_OP_nop
        }
        if (value.bytes() < addressBytes) { constant(out, mask(value.bytes())); out.write(0x1a); }
    }

    private static void offset(ByteArrayOutputStream out, int value, ByteOrder order) {
        if (value < 0 || value > Short.MAX_VALUE) throw new IllegalArgumentException("call-value branch too large");
        out.write(order == ByteOrder.LITTLE_ENDIAN ? value : value >>> 8);
        out.write(order == ByteOrder.LITTLE_ENDIAN ? value >>> 8 : value);
    }
    private static void constant(ByteArrayOutputStream out, long value) { out.write(0x10); uleb(out, value); }
    private static void uleb(ByteArrayOutputStream out, long value) {
        do {
            int next = (int) (value & 0x7f); value >>>= 7;
            out.write(next | (value == 0 ? 0 : 0x80));
        } while (value != 0);
    }
    private static long signExtend(long value, int bytes) { return bytes == 8 ? value : value << (64 - bytes * 8) >> (64 - bytes * 8); }
    private static long mask(int bytes) { return bytes == 8 ? -1L : (1L << (bytes * 8)) - 1; }
    private static void width(int bytes) {
        if (bytes < 1 || bytes > 8) throw new IllegalArgumentException("integer width must be 1..8 bytes");
    }
    private static void bound(int nodes, int depth) {
        if (nodes > 256 || depth > 32) throw new IllegalArgumentException("call-value expression budget exceeded");
    }
}
