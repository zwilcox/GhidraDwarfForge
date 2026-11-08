package ghidradwarfforge.unwind;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CancellationException;

import ghidradwarfforge.unwind.OriginalFrameRanges.*;

public final class OriginalFrameRangesSmoke {
    private record Fixture(byte[] bytes, int fde, int pointer, int address, int size,
            int cieAugmentation, int fdeAugmentation, int idWidth) { }
    private static int checks;
    private static void require(boolean ok, String message) { if (!ok) throw new AssertionError(message); checks++; }
    private static void reject(Runnable action) {
        try { action.run(); throw new AssertionError("invalid frame coverage accepted"); }
        catch (IllegalArgumentException expected) { checks++; }
    }
    private static void put(ByteBuffer out, long value, int bytes) {
        switch (bytes) {
            case 1 -> out.put((byte) value);
            case 2 -> out.putShort((short) value);
            case 4 -> out.putInt((int) value);
            case 8 -> out.putLong(value);
            default -> throw new AssertionError(bytes);
        }
    }
    private static void scalar(ByteBuffer out, long value, int format, int width) {
        if (format == 1 || format == 9) {
            boolean more;
            do {
                int next = (int) value & 127;
                value = format == 9 ? value >> 7 : value >>> 7;
                more = format == 9 ? !((value == 0 && (next & 64) == 0) ||
                    (value == -1 && (next & 64) != 0)) : value != 0;
                out.put((byte) (next | (more ? 128 : 0)));
            } while (more);
        }
        else put(out, value, switch (format) {
            case 2, 10 -> 2; case 3, 11 -> 4; case 4, 12 -> 8; default -> width;
        });
    }
    private static int header(ByteBuffer out, boolean wide, long identity) {
        int start = out.position();
        if (wide) out.putInt(-1).putLong(0).putLong(identity);
        else out.putInt(0).putInt((int) identity);
        return start;
    }
    private static void finish(ByteBuffer out, int start, boolean wide, int alignment) {
        while (out.position() % alignment != 0) out.put((byte) 0);
        if (wide) out.putLong(start + 4, out.position() - start - 12);
        else out.putInt(start, out.position() - start - 4);
    }
    private static Fixture fixture(boolean wide, ByteOrder order, int width, Format format,
            int version, String augmentation, int encoding, long address, long size) {
        boolean eh = format == Format.EH_FRAME;
        var out = ByteBuffer.allocate(512).order(order);
        int cie = header(out, wide, eh ? 0 : -1L);
        out.put((byte) version);
        for (char next : augmentation.toCharArray()) out.put((byte) next);
        out.put((byte) 0);
        if (version == 4) out.put((byte) width).put((byte) 0);
        out.put((byte) 1).put((byte) 0x78).put((byte) 16);
        int cieAug = out.position();
        if (!augmentation.isEmpty()) {
            out.put((byte) 0);
            for (char kind : augmentation.substring(1).toCharArray()) {
                switch (kind) {
                    case 'R' -> out.put((byte) encoding);
                    case 'L' -> out.put((byte) 0xff);
                    case 'P' -> out.put((byte) 0x9b).putInt(0x1234);
                    default -> { }
                }
            }
            out.put(cieAug, (byte) (out.position() - cieAug - 1));
        }
        finish(out, cie, wide, width);
        int fde = out.position(), pointer = fde + (wide ? 12 : 4);
        header(out, wide, eh ? pointer : 0);
        int at = out.position();
        int scalar = eh ? encoding & 15 : 0;
        scalar(out, eh && (encoding & 0x70) == 0x10 ? address - (0x5000 + at) : address, scalar, width);
        int range = out.position(); scalar(out, size, scalar, width);
        int fdeAug = out.position();
        if (!augmentation.isEmpty()) out.put((byte) 0);
        finish(out, fde, wide, width);
        return new Fixture(Arrays.copyOf(out.array(), out.position()), fde, pointer, at, range, cieAug, fdeAug, wide ? 8 : 4);
    }
    private static Inventory read(byte[] bytes, ByteOrder order, int width, Format format) {
        return OriginalFrameRanges.read(bytes, order, width, format, 0x5000, () -> false);
    }
    private static byte[] change(Fixture fixture, ByteOrder order, int offset, int width, long value) {
        byte[] result = fixture.bytes().clone();
        var out = ByteBuffer.wrap(result).order(order); out.position(offset); put(out, value, width);
        return result;
    }
    private static void check(boolean wide, ByteOrder order, int width, Format format, int version) {
        boolean eh = format == Format.EH_FRAME;
        var f = fixture(wide, order, width, format, version, eh ? "zR" : "", eh ? 0x1b : 0, 0x1000, 0x20);
        byte[] unchanged = f.bytes().clone();
        var result = read(f.bytes(), order, width, format);
        require(result.cies() == 1 && result.frames().size() == 1, "wrong record counts");
        var frame = result.frames().getFirst();
        require(frame.offset() == f.fde() && frame.cieOffset() == 0 && frame.address() == 0x1000 &&
            frame.size() == 0x20 && !frame.signalFrame(), "incorrect FDE pointer or address");
        require(Arrays.equals(unchanged, f.bytes()), "coverage reader mutated input");
        try { result.frames().clear(); throw new AssertionError("mutable inventory"); }
        catch (UnsupportedOperationException expected) { checks++; }
        for (int end = 1; end < f.bytes().length; end++) {
            if (end == f.fde()) continue; // A complete lone CIE has no covered intervals.
            int length = end;
            reject(() -> read(Arrays.copyOf(f.bytes(), length), order, width, format));
        }
        reject(() -> read(change(f, order, f.pointer(), f.idWidth(), eh ? f.pointer() + 1 : 1), order, width, format));
        reject(() -> read(change(f, order, 0, 4, 0xffff_fff0L), order, width, format));
        reject(() -> read(change(f, order, wide ? 4 : 0, wide ? 8 : 4, Long.MAX_VALUE), order, width, format));
        if (version == 4) {
            int addressSize = (wide ? 20 : 8) + 1 + (eh ? 3 : 1);
            reject(() -> read(change(f, order, addressSize, 1, width == 4 ? 8 : 4), order, width, format));
            reject(() -> read(change(f, order, addressSize + 1, 1, 1), order, width, format));
        }
        if (eh) {
            reject(() -> read(change(f, order, f.cieAugmentation(), 1, 0x7f), order, width, format));
            reject(() -> read(change(f, order, f.fdeAugmentation(), 1, 0x7f), order, width, format));
            reject(() -> read(change(f, order, f.cieAugmentation() + 1, 1, 0x9b), order, width, format));
            reject(() -> read(change(f, order, f.cieAugmentation() + 1, 1, 0x3b), order, width, format));
            var terminated = Arrays.copyOf(f.bytes(), f.bytes().length + 8);
            require(read(terminated, order, width, format).frames().equals(result.frames()), "zero terminator changed coverage");
            terminated[terminated.length - 1] = 1;
            reject(() -> read(terminated, order, width, format));
            var signal = fixture(wide, order, width, format, version, "zPLRS", 0x1b, 0x1000, 0x20);
            require(read(signal.bytes(), order, width, format).frames().getFirst().signalFrame(), "signal augmentation lost");
            var unknown = fixture(wide, order, width, format, version, "zRX", 0x1b, 0x1000, 0x20);
            reject(() -> read(unknown.bytes(), order, width, format));
            var repeated = fixture(wide, order, width, format, version, "zRR", 0x1b, 0x1000, 0x20);
            reject(() -> read(repeated.bytes(), order, width, format));
        }
        else {
            byte[] forward = new byte[f.bytes().length];
            int fdeLength = forward.length - f.fde();
            System.arraycopy(f.bytes(), f.fde(), forward, 0, fdeLength);
            System.arraycopy(f.bytes(), 0, forward, fdeLength, f.fde());
            var buffer = ByteBuffer.wrap(forward).order(order);
            buffer.position(wide ? 12 : 4); put(buffer, fdeLength, f.idWidth());
            require(read(forward, order, width, format).frames().getFirst().cieOffset() == fdeLength, "forward CIE not resolved");
            reject(() -> read(new byte[4], order, width, format));
        }
        int[] polls = {0};
        OriginalFrameRanges.read(f.bytes(), order, width, format, 0x5000, () -> { polls[0]++; return false; });
        for (int stop = 1; stop <= polls[0]; stop++) {
            int limit = stop; int[] seen = {0};
            try {
                OriginalFrameRanges.read(f.bytes(), order, width, format, 0x5000, () -> ++seen[0] == limit);
                throw new AssertionError("ignored coverage cancellation");
            }
            catch (CancellationException expected) { checks++; }
        }
        require(read(f.bytes(), order, width, format).equals(result), "cancelled scan poisoned retry");
    }
    public static void main(String[] args) throws Exception {
        if (args.length != 0) {
            var result = OriginalFrameRanges.read(Files.readAllBytes(Path.of(args[0])),
                args[1].equals("little") ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN,
                Integer.parseInt(args[2]), Format.valueOf(args[3]), Long.decode(args[4]), () -> false);
            System.out.println("cies " + result.cies());
            for (var frame : result.frames()) System.out.printf("%x %x %x %x %s%n",
                frame.offset(), frame.cieOffset(), frame.address(), frame.size(), frame.signalFrame());
            return;
        }
        for (boolean wide : List.of(false, true)) for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
            for (int width : List.of(4, 8)) for (Format format : Format.values()) for (int version : List.of(1, 3, 4)) {
                check(wide, order, width, format, version);
            }
        }
        for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
            for (int encoding : List.of(0, 1, 2, 3, 4, 9, 10, 11, 12)) for (int relative : List.of(0, 0x10)) {
                var encoded = fixture(false, order, 8, Format.EH_FRAME, 1, "zR", encoding | relative, 0x6000, 0x33);
                var frame = read(encoded.bytes(), order, 8, Format.EH_FRAME).frames().getFirst();
                require(frame.address() == 0x6000 && frame.size() == 0x33, "wrong scalar or relative encoding");
                if (encoding >= 9 && relative != 0) {
                    var negative = fixture(false, order, 8, Format.EH_FRAME, 1, "zR", encoding | relative, 0x1000, 0x33);
                    require(read(negative.bytes(), order, 8, Format.EH_FRAME).frames().getFirst().address() == 0x1000,
                        "signed negative PC-relative displacement lost");
                }
            }
            var good = fixture(false, order, 8, Format.DEBUG_FRAME, 4, "", 0, 0x1000, 0x20);
            byte[] late = Arrays.copyOf(good.bytes(), good.bytes().length + 8);
            ByteBuffer.wrap(late).order(order).putInt(good.bytes().length, 100);
            reject(() -> read(late, order, 8, Format.DEBUG_FRAME));
            var badVersion = fixture(false, order, 8, Format.DEBUG_FRAME, 2, "", 0, 0x1000, 0x20);
            reject(() -> read(badVersion.bytes(), order, 8, Format.DEBUG_FRAME));
            byte[] badLeb = good.bytes().clone();
            Arrays.fill(badLeb, 12, good.fde(), (byte) 0x80);
            reject(() -> read(badLeb, order, 8, Format.DEBUG_FRAME));
            var negativeSize = fixture(false, order, 8, Format.EH_FRAME, 1, "zR", 0x1b, 0x1000, -1);
            reject(() -> read(negativeSize.bytes(), order, 8, Format.EH_FRAME));
        }
        var order = ByteOrder.LITTLE_ENDIAN;
        var unsignedOverflow = fixture(false, order, 8, Format.EH_FRAME, 1, "zR", 0x14, 0x1000, 0x20);
        reject(() -> read(unsignedOverflow.bytes(), order, 8, Format.EH_FRAME));
        reject(() -> OriginalFrameRanges.read(new byte[0], order, 4, Format.EH_FRAME, 0x1_0000_0000L, () -> false));
        var zero = fixture(false, order, 8, Format.DEBUG_FRAME, 4, "", 0, 0x1000, 0);
        require(read(zero.bytes(), order, 8, Format.DEBUG_FRAME).frames().getFirst().size() == 0, "empty FDE invented coverage");
        var overflow = fixture(false, order, 8, Format.DEBUG_FRAME, 4, "", 0, Long.MAX_VALUE, 2);
        reject(() -> read(overflow.bytes(), order, 8, Format.DEBUG_FRAME));
        var narrow = fixture(false, order, 4, Format.DEBUG_FRAME, 4, "", 0, 0xffff_ffffL, 2);
        reject(() -> read(narrow.bytes(), order, 4, Format.DEBUG_FRAME));
        var last = fixture(false, order, 4, Format.DEBUG_FRAME, 4, "", 0, 0xffff_ffffL, 1);
        require(read(last.bytes(), order, 4, Format.DEBUG_FRAME).frames().getFirst().address() == 0xffff_ffffL, "last ELF32 byte lost");
        require(read(new byte[0], order, 8, Format.DEBUG_FRAME).frames().isEmpty(), "empty section is not empty");
        System.out.println("original-frame-ranges-smoke=PASS checks=" + checks);
    }
}
