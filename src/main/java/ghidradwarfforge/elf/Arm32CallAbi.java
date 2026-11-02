package ghidradwarfforge.elf;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/** Bounded AAELF32/addenda32 observation, distinct from GDB's attribute-based choice. */
public final class Arm32CallAbi {
    public enum Pcs { BASE, VFP, COMPATIBLE, UNKNOWN }
    public record Observation(Pcs declared, Pcs consumer, boolean attributesPresent, String restriction) {
        public boolean valid() { return restriction.isEmpty(); }
    }

    private Arm32CallAbi() { }

    public static Observation observe(ElfImage image, BooleanSupplier cancelled) throws IOException {
        check(cancelled);
        var sections = image.sections().stream()
            .filter(s -> s.type == 0x70000003 || s.name.equals(".ARM.attributes")).toList();
        byte[] header = image.headerBytes();
        long flags = image.flags();
        if (image.machine() != 40 || image.is64Bit() || (image.type() != 2 && image.type() != 3) ||
                (header[7] != 0 && header[7] != 3) || header[8] != 0 ||
                (flags & ~0x00800600L) != 0x05000000L || (flags & 0x600) == 0x600 ||
                ((flags & 0x00800000L) != 0) != (image.byteOrder() == ByteOrder.BIG_ENDIAN)) {
            return invalid(!sections.isEmpty(), "requires unambiguous EABI5 Linux/System V ARM LE or BE8 metadata");
        }
        Pcs declared = (flags & 0x400) == 0 ? Pcs.BASE : Pcs.VFP;
        if (sections.isEmpty()) {
            // GDB 17.1 arm_gdbarch_init defaults absent Tag_ABI_VFP_args to 0,
            // even when EF_ARM_ABI_FLOAT_HARD declares a VFP executable.
            return new Observation(declared, Pcs.BASE, false, "");
        }
        if (sections.size() != 1) return invalid(true, "multiple ARM attribute sections");
        var section = sections.getFirst();
        if (section.type != 0x70000003 || section.size < 1 || section.size > 65536 || section.flags != 0) {
            return invalid(true, "invalid or oversized ARM attribute section");
        }
        byte[] bytes = image.readSourceRange(section.offset, section.size, "ARM call ABI attributes");
        try {
            var reader = new Reader(bytes, image.byteOrder(), cancelled);
            require(reader.byteValue(bytes.length) == 'A', "unsupported ARM attribute format");
            Map<Integer, Long> attributes = null;
            while (reader.position < bytes.length) {
                check(cancelled);
                int start = reader.position;
                long length = reader.word(bytes.length);
                require(length >= 5 && length <= bytes.length - start, "invalid ARM vendor extent");
                int end = start + (int) length;
                String vendor = reader.string(end);
                if (!vendor.equals("aeabi")) {
                    reader.position = end;
                    continue;
                }
                while (reader.position < end) {
                    int scopeStart = reader.position;
                    long scope = reader.uleb(end);
                    long scopeLength = reader.word(end);
                    require(scopeLength >= reader.position - scopeStart && scopeLength <= end - scopeStart,
                        "invalid ARM attribute scope extent");
                    int scopeEnd = scopeStart + (int) scopeLength;
                    require(scope == 1, "section/symbol-scoped ARM ABI attributes need separate classification");
                    require(attributes == null, "multiple AEABI file scopes");
                    attributes = reader.attributes(scopeEnd);
                }
            }
            require(attributes != null, "no AEABI file scope");
            require(!attributes.containsKey(64) || attributes.containsKey(28),
                "Tag_nodefaults leaves the floating PCS unspecified");
            long value = attributes.getOrDefault(28, 0L);
            Pcs attributePcs = value == 0 ? Pcs.BASE : value == 1 ? Pcs.VFP :
                value == 3 ? Pcs.COMPATIBLE : Pcs.UNKNOWN;
            require(attributePcs != Pcs.UNKNOWN, "toolchain-specific or unknown floating PCS attribute");
            require(attributePcs == Pcs.COMPATIBLE || attributePcs == declared,
                "ARM floating PCS flags contradict build attributes");
            require(attributes.getOrDefault(29, 0L) == 0, "WMMX argument ABI needs separate classification");
            return new Observation(attributePcs == Pcs.COMPATIBLE ? Pcs.COMPATIBLE : declared,
                attributePcs == Pcs.VFP ? Pcs.VFP : Pcs.BASE, true, "");
        }
        catch (IllegalArgumentException malformed) {
            return invalid(true, malformed.getMessage());
        }
    }

    private static Observation invalid(boolean present, String reason) {
        return new Observation(Pcs.UNKNOWN, Pcs.UNKNOWN, present, "ARM call ABI: " + reason);
    }

    private static void require(boolean value, String message) {
        if (!value) throw new IllegalArgumentException(message);
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("ARM call ABI observation cancelled");
    }

    private static final class Reader {
        private final byte[] bytes;
        private final ByteOrder order;
        private final BooleanSupplier cancelled;
        private int position;

        private Reader(byte[] bytes, ByteOrder order, BooleanSupplier cancelled) {
            this.bytes = bytes;
            this.order = order;
            this.cancelled = cancelled;
        }

        private int byteValue(int end) {
            check(cancelled);
            require(position < end, "truncated ARM attribute");
            return Byte.toUnsignedInt(bytes[position++]);
        }

        private long word(int end) {
            check(cancelled);
            require(end - position >= 4, "truncated ARM attribute length");
            long value = Integer.toUnsignedLong(ByteBuffer.wrap(bytes, position, 4).order(order).getInt());
            position += 4;
            return value;
        }

        private long uleb(int end) {
            long result = 0;
            for (int shift = 0; shift <= 28; shift += 7) {
                int value = byteValue(end);
                require(shift != 28 || value <= 15, "overflowing ARM attribute ULEB128");
                result |= (long) (value & 127) << shift;
                if ((value & 128) == 0) return result;
            }
            throw new IllegalArgumentException("unterminated ARM attribute ULEB128");
        }

        private String string(int end) {
            int start = position;
            while (byteValue(end) != 0) { }
            return new String(bytes, start, position - start - 1, StandardCharsets.US_ASCII);
        }

        private Map<Integer, Long> attributes(int end) {
            var result = new HashMap<Integer, Long>();
            while (position < end) {
                long tag = uleb(end);
                require(tag >= 4 && tag <= Integer.MAX_VALUE, "invalid ARM attribute tag");
                require(tag <= 32 || java.util.Set.of(34L, 36L, 38L, 42L, 44L, 46L, 48L, 50L, 52L).contains(tag) ||
                    tag % 128 >= 64, "unknown mandatory ARM attribute tag");
                require(!result.containsKey((int) tag), "duplicate ARM attribute tag");
                long value = 0;
                if (tag == 4 || tag == 5 || (tag > 32 && (tag & 1) != 0)) {
                    string(end);
                }
                else {
                    value = uleb(end);
                    if (tag == 32) {
                        string(end);
                        require(value == 0, "toolchain compatibility ABI requires separate classification");
                    }
                }
                result.put((int) tag, value);
            }
            return result;
        }
    }
}
