package ghidradwarfforge.dwarf;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

import ghidradwarfforge.unwind.CallFramePlan;
import ghidradwarfforge.unwind.OriginalFrameRanges;
import ghidradwarfforge.unwind.CallFramePlan.*;

/** DWARF 5 section, CIE version 4, DWARF32 lengths; no architecture inference. */
public final class DwarfDebugFrame {
    private static final int MAX_ROWS = 1_000_000;
    private static final int MAX_SECTION_BYTES = 64 * 1024 * 1024;

    private DwarfDebugFrame() { }

    public static byte[] build(CallFramePlan plan, BooleanSupplier cancelled) {
        return build(plan, 0, cancelled);
    }

    /**
     * Preserve a decoded original section as an exact prefix and append disjoint
     * generated records. This checks packaging/coverage, not original CFI semantics
     * or the recovery evidence behind the plan. ELF source/relocation qualification
     * remains the caller's responsibility; this is not a writer collision bypass.
     */
    public static byte[] append(byte[] original, CallFramePlan plan, BooleanSupplier cancelled) {
        Objects.requireNonNull(original, "original frame bytes");
        Objects.requireNonNull(plan, "plan");
        Objects.requireNonNull(cancelled, "cancelled");
        checkCancelled(cancelled);
        if (original.length == 0) return build(plan, cancelled);
        if (original.length > MAX_SECTION_BYTES || original.length % plan.addressBytes() != 0) {
            throw new IllegalArgumentException("original frame prefix exceeds size or alignment bounds");
        }
        var inventory = OriginalFrameRanges.read(original, plan.order(), plan.addressBytes(),
            OriginalFrameRanges.Format.DEBUG_FRAME, 0, cancelled);
        var sorted = new ArrayList<>(inventory.frames());
        sorted.sort((left, right) -> Long.compareUnsigned(left.address(), right.address()));
        var intervals = new java.util.TreeMap<Long, Long>(Long::compareUnsigned);
        for (var frame : sorted) {
            checkCancelled(cancelled);
            if (frame.size() == 0) continue;
            long end = frame.address() + frame.size() - 1;
            var prior = intervals.lastEntry();
            if (prior != null && Long.compareUnsigned(prior.getValue(), frame.address()) >= 0) {
                if (Long.compareUnsigned(end, prior.getValue()) > 0) intervals.put(prior.getKey(), end);
            }
            else intervals.put(frame.address(), end);
        }
        for (var frame : plan.frames()) {
            checkCancelled(cancelled);
            var prior = intervals.floorEntry(frame.address());
            var next = intervals.ceilingEntry(frame.address());
            if ((prior != null && Long.compareUnsigned(prior.getValue(), frame.address()) >= 0) ||
                    (next != null && Long.compareUnsigned(next.getKey(), frame.address() + frame.size() - 1) <= 0)) {
                throw new IllegalArgumentException("generated frame overlaps original coverage");
            }
        }
        byte[] generated = build(plan, original.length, cancelled);
        if (generated.length > MAX_SECTION_BYTES - original.length) {
            throw new IllegalArgumentException("combined frame section budget exceeded");
        }
        byte[] result = new byte[original.length + generated.length];
        for (int offset = 0; offset < original.length; offset += 32768) {
            checkCancelled(cancelled);
            System.arraycopy(original, offset, result, offset, Math.min(32768, original.length - offset));
        }
        for (int offset = 0; offset < generated.length; offset += 32768) {
            checkCancelled(cancelled);
            System.arraycopy(generated, offset, result, original.length + offset, Math.min(32768, generated.length - offset));
        }
        checkCancelled(cancelled);
        return result;
    }

    private static byte[] build(CallFramePlan plan, int sectionOffset, BooleanSupplier cancelled) {
        Objects.requireNonNull(plan, "plan");
        Objects.requireNonNull(cancelled, "cancelled");
        checkCancelled(cancelled);
        var frames = new ArrayList<>(plan.frames());
        frames.sort((left, right) -> Long.compareUnsigned(left.address(), right.address()));
        int rows = 0;
        Frame previous = null;
        for (Frame frame : frames) {
            checkCancelled(cancelled);
            if (plan.addressBytes() == 4 &&
                    (Long.compareUnsigned(frame.address(), 0xffff_ffffL) > 0 ||
                     frame.size() > 0xffff_ffffL ||
                     Long.compareUnsigned(frame.address() + frame.size() - 1, 0xffff_ffffL) > 0)) {
                throw new IllegalArgumentException("frame exceeds 32-bit target address space");
            }
            if (previous != null && Long.compareUnsigned(previous.address() + previous.size() - 1,
                    frame.address()) >= 0) {
                throw new IllegalArgumentException("overlapping frame ranges");
            }
            previous = frame;
            rows = Math.addExact(rows, frame.rows().size());
            if (rows > MAX_ROWS) throw new IllegalArgumentException("frame row budget exceeded");
            for (Row row : frame.rows()) {
                checkCancelled(cancelled);
                if (!row.rules().keySet().equals(plan.registers()) || !plan.registers().contains(row.cfa().register())) {
                    throw new IllegalArgumentException("frame row is incomplete for the declared register universe");
                }
                for (Rule rule : row.rules().values()) {
                    if (rule instanceof InRegister in && !plan.registers().contains(in.register())) {
                        throw new IllegalArgumentException("frame recovery register is outside the declared universe");
                    }
                }
            }
        }
        if (frames.isEmpty()) return new byte[0];
        Buffer out = new Buffer(plan.order());
        int cie = out.size();
        out.integer(0, 4);
        out.integer(0xffff_ffffL, 4);
        out.octet(4); // CIE version, independent of the CU's DWARF 5 version.
        out.octet(0); // no augmentation
        out.octet(plan.addressBytes());
        out.octet(0); // no segment selector
        out.uleb(1); // byte-sized code alignment; no target instruction assumption
        out.sleb(1); // signed offsets remain exact bytes
        out.uleb(plan.returnRegister());
        Map<Integer, Rule> initial = plan.initialRules();
        for (var rule : initial.entrySet()) {
            checkCancelled(cancelled);
            writeRule(out, rule.getKey(), rule.getValue());
        }
        out.finishEntry(cie, plan.addressBytes());
        for (Frame frame : frames) {
            checkCancelled(cancelled);
            int entry = out.size();
            out.integer(0, 4);
            out.integer(sectionOffset + cie, 4); // section-relative .debug_frame CIE pointer
            out.integer(frame.address(), plan.addressBytes());
            out.integer(frame.size(), plan.addressBytes());
            Cfa priorCfa = null;
            Map<Integer, Rule> priorRules = initial;
            long address = frame.address();
            for (Row row : frame.rows()) {
                checkCancelled(cancelled);
                if (row.cfa().equals(priorCfa) && row.rules().equals(priorRules)) continue;
                long delta = row.address() - address;
                if (delta != 0) {
                    if (delta <= 0xffff_ffffL) {
                        out.octet(0x04); // DW_CFA_advance_loc4
                        out.integer(delta, 4);
                    }
                    else {
                        out.octet(0x01); // DW_CFA_set_loc for a larger proven gap
                        out.integer(row.address(), plan.addressBytes());
                    }
                    address = row.address();
                }
                if (!row.cfa().equals(priorCfa)) {
                    out.octet(0x12); // DW_CFA_def_cfa_sf
                    out.uleb(row.cfa().register());
                    out.sleb(row.cfa().offset());
                }
                for (var rule : row.rules().entrySet()) {
                    checkCancelled(cancelled);
                    if (!rule.getValue().equals(priorRules.get(rule.getKey()))) {
                        writeRule(out, rule.getKey(), rule.getValue());
                    }
                }
                priorCfa = row.cfa();
                priorRules = row.rules();
            }
            out.finishEntry(entry, plan.addressBytes());
        }
        checkCancelled(cancelled);
        return out.toByteArray();
    }

    private static void writeRule(Buffer out, int register, Rule rule) {
        int opcode = switch (rule) {
            case Undefined unused -> 0x07;
            case SameValue unused -> 0x08;
            case AtCfaOffset unused -> 0x11;
            case CfaValue unused -> 0x16; // DW_CFA_val_expression
            case InRegister unused -> 0x09;
        };
        out.octet(opcode);
        out.uleb(register);
        switch (rule) {
            case AtCfaOffset at -> out.sleb(at.offset());
            case CfaValue value -> {
                // DWARF 5 6.4.2.3 starts this expression with the CFA on the
                // stack. LLDB 18 stops parsing a CIE at DW_CFA_val_offset_sf;
                // an equivalent expression preserves subsequent register rules.
                // DW_OP_call_frame_cfa is forbidden in CFI expressions.
                Buffer expression = new Buffer(out.order);
                if (value.offset() >= 0) {
                    expression.octet(0x23); // DW_OP_plus_uconst
                    expression.uleb(value.offset());
                }
                else {
                    expression.octet(0x11); // DW_OP_consts
                    expression.sleb(value.offset());
                    expression.octet(0x22); // DW_OP_plus
                }
                out.uleb(expression.size());
                for (byte octet : expression.toByteArray()) out.octet(octet & 0xff);
            }
            case InRegister in -> out.uleb(in.register());
            default -> { }
        }
    }

    private static void checkCancelled(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("frame serialization cancelled");
    }

    private static final class Buffer extends ByteArrayOutputStream {
        private final ByteOrder order;

        private Buffer(ByteOrder order) { this.order = order; }

        private void octet(int value) {
            if (count >= MAX_SECTION_BYTES) throw new IllegalArgumentException("frame section budget exceeded");
            write(value);
        }

        private void integer(long value, int width) {
            for (int i = 0; i < width; i++) {
                int shift = (order == ByteOrder.LITTLE_ENDIAN ? i : width - i - 1) * 8;
                octet((int) (value >>> shift) & 0xff);
            }
        }

        private void uleb(long value) {
            do {
                int part = (int) value & 0x7f;
                value >>>= 7;
                octet(value == 0 ? part : part | 0x80);
            } while (value != 0);
        }

        private void sleb(long value) {
            boolean more;
            do {
                int part = (int) value & 0x7f;
                value >>= 7;
                more = !((value == 0 && (part & 0x40) == 0) || (value == -1 && (part & 0x40) != 0));
                octet(more ? part | 0x80 : part);
            } while (more);
        }

        private void finishEntry(int start, int alignment) {
            while ((count - start) % alignment != 0) octet(0); // DW_CFA_nop
            ByteBuffer.wrap(buf).order(order).putInt(start, count - start - 4);
        }
    }
}
