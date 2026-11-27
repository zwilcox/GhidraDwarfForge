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
    private record Auxiliary(int lsda, int personality) { }
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
        return fixture(wide, order, width, format, version, augmentation, encoding, address, size,
            new Auxiliary(0xff, 0x9b));
    }
    private static Fixture fixture(boolean wide, ByteOrder order, int width, Format format,
            int version, String augmentation, int encoding, long address, long size, Auxiliary auxiliary) {
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
                    case 'L' -> out.put((byte) auxiliary.lsda());
                    case 'P' -> {
                        out.put((byte) auxiliary.personality());
                        scalar(out, 0x1234, auxiliary.personality() & 15, width);
                    }
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
        if (!augmentation.isEmpty()) {
            out.put((byte) 0);
            if (augmentation.indexOf('L') >= 0 && auxiliary.lsda() != 0xff) {
                scalar(out, 0, auxiliary.lsda() & 15, width);
            }
            out.put(fdeAug, (byte) (out.position() - fdeAug - 1));
        }
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
    /** LSB 5.0 core, tables 10-5/10-6; aligned encodings are outside this reader's profile. */
    private static void augmentationEncodings() {
        // https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic.pdf
        var skipped = new java.util.HashSet<Integer>();
        var resolved = new java.util.HashSet<Integer>();
        for (int scalar : List.of(0, 1, 2, 3, 4, 9, 10, 11, 12)) {
            resolved.add(scalar);
            resolved.add(0x10 + scalar);
            for (int application : List.of(0, 0x10, 0x20, 0x30, 0x40)) {
                skipped.add(application + scalar);
                skipped.add(0x80 + application + scalar);
            }
        }
        require(skipped.size() == 90 && resolved.size() == 18, "encoding inventory changed");
        int cases = 0;
        for (boolean wide : List.of(false, true)) {
            for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                for (int width : List.of(4, 8)) {
                    for (char kind : new char[] {'L', 'P', 'R'}) {
                        for (int encoding = 0; encoding <= 255; encoding++) {
                            boolean supported = kind == 'R' ? resolved.contains(encoding) :
                                skipped.contains(encoding) || kind == 'L' && encoding == 0xff;
                            var f = fixture(wide, order, width, Format.EH_FRAME, 4, "z" + kind,
                                kind == 'R' ? encoding : 0, 0x6000, 0x33,
                                new Auxiliary(kind == 'L' ? encoding : 0xff, kind == 'P' ? encoding : 0x9b));
                            byte[] original = f.bytes().clone();
                            String context = kind + " encoding=" + Integer.toHexString(encoding) + " width=" + width +
                                " wide=" + wide + " " + order;
                            if (supported) {
                                var inventory = read(f.bytes(), order, width, Format.EH_FRAME);
                                require(inventory.cies() == 1 && inventory.frames().equals(List.of(
                                    new Frame(f.fde(), 0, 0x6000, 0x33, false))), "wrong framed inventory " + context);
                            }
                            else {
                                try {
                                    read(f.bytes(), order, width, Format.EH_FRAME);
                                    throw new AssertionError("unsupported encoding accepted " + context);
                                }
                                catch (IllegalArgumentException expected) {
                                    String reason = switch (kind) {
                                        case 'L' -> "unsupported LSDA encoding";
                                        case 'P' -> "unsupported personality encoding";
                                        case 'R' -> "unsupported FDE pointer";
                                        default -> throw new AssertionError(kind);
                                    };
                                    require(expected.getMessage().contains(reason), "wrong rejection " + context + ": " + expected);
                                }
                            }
                            require(Arrays.equals(original, f.bytes()), "encoding scan changed bytes " + context);
                            cases++;
                        }
                    }
                }
            }
        }
        require(cases == 6144, "incomplete augmentation encoding matrix");
        System.out.println("original-frame-augmentation-encodings=PASS cases=" + cases);
    }

    private static byte[] hex(String value) { return java.util.HexFormat.of().parseHex(value); }

    /** Raw variable-length fields keep malformed encodings independent of the fixture encoder. */
    private static Fixture rawLeb(ByteOrder order, int encoding, byte[] address, byte[] size,
            byte[] cieLength, byte[] fdeLength) {
        var out = ByteBuffer.allocate(256).order(order);
        int cie = header(out, false, 0);
        out.put(new byte[] {1, 'z', 'R', 0, 1, 0x78, 16});
        int cieAugmentation = out.position();
        out.put(cieLength).put((byte) encoding);
        finish(out, cie, false, 8);
        int fde = out.position(), pointer = fde + 4;
        header(out, false, pointer);
        int at = out.position();
        out.put(address);
        int range = out.position();
        out.put(size);
        int augmentation = out.position();
        out.put(fdeLength);
        finish(out, fde, false, 8);
        return new Fixture(Arrays.copyOf(out.array(), out.position()), fde, pointer, at, range,
            cieAugmentation, augmentation, 4);
    }

    private static Fixture rawLeb(ByteOrder order, int encoding, byte[] address, byte[] size) {
        return rawLeb(order, encoding, address, size, new byte[] {1}, new byte[] {0});
    }

    private static void expectedLeb(Fixture fixture, ByteOrder order, long address, long size) {
        byte[] unchanged = fixture.bytes().clone();
        Inventory inventory;
        try { inventory = read(fixture.bytes(), order, 8, Format.EH_FRAME); }
        catch (IllegalArgumentException rejected) {
            throw new AssertionError("valid raw LEB frame was rejected; expected address=" + address + " size=" + size, rejected);
        }
        require(inventory.cies() == 1 && inventory.frames().equals(List.of(
            new Frame(fixture.fde(), 0, address, size, false))), "wrong raw LEB frame inventory");
        require(Arrays.equals(unchanged, fixture.bytes()), "LEB decoding changed input");
    }

    private static void rejectedFrame(Fixture fixture, ByteOrder order, int width, Format format, String reason) {
        byte[] unchanged = fixture.bytes().clone();
        try {
            read(fixture.bytes(), order, width, format);
            throw new AssertionError("accepted malformed frame: " + reason);
        }
        catch (IllegalArgumentException expected) {
            require(expected.getMessage().contains(reason), "wrong malformed-frame rejection: " + expected);
        }
        require(Arrays.equals(unchanged, fixture.bytes()), "rejected frame changed input");
    }

    private static void lebBoundaries() {
        byte[] zero = {0}, one = {1};
        byte[] zeroTen = hex("80".repeat(9) + "00");
        byte[] oneTen = hex("81" + "80".repeat(8) + "00");
        byte[] unsignedMax = hex("ff".repeat(8) + "7f");
        byte[] signedMax = hex("ff".repeat(9) + "00");
        byte[] negativeOne = hex("ff".repeat(9) + "7f");
        byte[] unsignedHigh = hex("80".repeat(9) + "01");
        byte[] signedMin = hex("80".repeat(9) + "7f");
        int cases = 0;
        for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
            expectedLeb(rawLeb(order, 1, zeroTen, oneTen), order, 0, 1);
            expectedLeb(rawLeb(order, 9, zeroTen, oneTen), order, 0, 1);
            expectedLeb(rawLeb(order, 1, unsignedMax, one), order, Long.MAX_VALUE, 1);
            expectedLeb(rawLeb(order, 9, signedMax, one), order, Long.MAX_VALUE, 1);
            var relative = rawLeb(order, 0x19, negativeOne, one);
            expectedLeb(relative, order, 0x5000 + relative.address() - 1, 1);
            expectedLeb(rawLeb(order, 1, unsignedHigh, zero), order, Long.MIN_VALUE, 0);
            expectedLeb(rawLeb(order, 9, signedMin, zero), order, Long.MIN_VALUE, 0);
            rejectedFrame(rawLeb(order, 9, zero, negativeOne), order, 8, Format.EH_FRAME, "FDE range exceeds");
            var positiveDelta = rawLeb(order, 0x19, signedMax, one);
            expectedLeb(positiveDelta, order, Long.MAX_VALUE + 0x5000 + positiveDelta.address(), 1);
            rejectedFrame(rawLeb(order, 0x19, signedMin, one), order, 8, Format.EH_FRAME, "escapes the target address space");
            expectedLeb(rawLeb(order, 1, unsignedMax, new byte[] {2}), order, Long.MAX_VALUE, 2);
            byte[] allBits = hex("ff".repeat(9) + "01");
            expectedLeb(rawLeb(order, 1, allBits, one), order, -1L, 1);
            rejectedFrame(rawLeb(order, 1, allBits, new byte[] {2}), order, 8, Format.EH_FRAME, "FDE extent overflows");
            rejectedFrame(rawLeb(order, 1, zero, one, unsignedHigh, zero), order, 8, Format.EH_FRAME,
                "CIE augmentation crosses record");
            rejectedFrame(rawLeb(order, 1, zero, one, one, unsignedHigh), order, 8, Format.EH_FRAME,
                "FDE augmentation crosses record");
            for (int encoding : new int[] {1, 9}) {
                for (int last = 0; last <= 255; last++) {
                    byte[] address = zeroTen.clone();
                    address[9] = (byte) last;
                    var fixture = rawLeb(order, encoding, address, one);
                    if (last == 0) expectedLeb(fixture, order, 0, 1);
                    else if (last == (encoding == 1 ? 1 : 127)) expectedLeb(fixture, order, Long.MIN_VALUE, 1);
                    else {
                        // The tenth group has only one significant bit. For signed
                        // values its other bits must replicate that bit's sign.
                        int high = encoding == 1 ? 1 : 127;
                        String reason = last == 128 || last == 128 + high ? "unterminated frame LEB128" : "overflowing frame LEB128";
                        rejectedFrame(fixture, order, 8, Format.EH_FRAME, reason);
                    }
                    cases++;
                }
            }
            for (String augmentation : List.of("z\u0080", "z" + "S".repeat(64))) {
                rejectedFrame(fixture(false, order, 8, Format.EH_FRAME, 1, augmentation, 0, 0x6000, 1),
                    order, 8, Format.EH_FRAME, "unsupported or excessive CIE augmentation string");
            }
            rejectedFrame(fixture(false, order, 8, Format.EH_FRAME, 1, "R", 0, 0x6000, 1),
                order, 8, Format.EH_FRAME, "unsupported CIE augmentation");
            rejectedFrame(fixture(false, order, 8, Format.DEBUG_FRAME, 4, "zR", 0, 0x6000, 1),
                order, 8, Format.DEBUG_FRAME, "unsupported CIE augmentation");
            int[] count = {0};
            var baseline = OriginalFrameRanges.read(relative.bytes(), order, 8, Format.EH_FRAME,
                0x5000, () -> { count[0]++; return false; });
            byte[] unchanged = relative.bytes().clone();
            for (int boundary = 1; boundary <= count[0]; boundary++) {
                int stop = boundary;
                int[] seen = {0};
                try {
                    OriginalFrameRanges.read(relative.bytes(), order, 8, Format.EH_FRAME, 0x5000, () -> ++seen[0] == stop);
                    throw new AssertionError("raw LEB scan ignored cancellation at " + stop);
                }
                catch (CancellationException expected) { require(seen[0] == stop, "scan exceeded cancellation boundary"); }
                require(Arrays.equals(unchanged, relative.bytes()), "cancelled LEB scan changed input");
                require(read(relative.bytes(), order, 8, Format.EH_FRAME).equals(baseline), "LEB cancellation poisoned retry");
            }
        }
        require(cases == 1024, "incomplete tenth-byte LEB matrix");
        System.out.println("original-frame-leb-boundaries=PASS cases=" + cases);
    }

    private static void parserLimits() throws Exception {
        var order = ByteOrder.LITTLE_ENDIAN;
        var ordinary = fixture(false, order, 8, Format.EH_FRAME, 1, "", 0, 0x1000, 1);
        byte[] cie = Arrays.copyOf(ordinary.bytes(), ordinary.fde());
        require(cie.length == 16, "limit fixture must be one complete 16-byte CIE");
        int records = 262144;
        byte[] many = new byte[records * cie.length];
        for (int offset = 0; offset < many.length; offset += cie.length) System.arraycopy(cie, 0, many, offset, cie.length);
        Inventory accepted;
        try { accepted = read(many, order, 8, Format.EH_FRAME); }
        catch (IllegalArgumentException failure) { throw new AssertionError("record limit rejected the supported boundary", failure); }
        require(accepted.cies() == records && accepted.frames().isEmpty(), "wrong inventory at record limit");
        byte[] excessive = Arrays.copyOf(many, many.length + cie.length);
        System.arraycopy(cie, 0, excessive, many.length, cie.length);
        expectFailure(() -> read(excessive, order, 8, Format.EH_FRAME), "frame record budget exceeded");

        byteLimit(cie);
        for (int width : new int[] {0, 1, 2, 3, 5, 16}) {
            expectFailure(() -> read(ordinary.bytes(), order, width, Format.EH_FRAME), "address width");
        }
        for (ByteOrder byteOrder : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
            var frame = fixture(true, byteOrder, 8, Format.DEBUG_FRAME, 4, "", 0, 0x1000, 1);
            for (long reference : new long[] {Long.MIN_VALUE, 0x80000000L, Long.MAX_VALUE}) {
                rejectedFrame(new Fixture(change(frame, byteOrder, frame.pointer(), 8, reference), frame.fde(),
                    frame.pointer(), frame.address(), frame.size(), frame.cieAugmentation(), frame.fdeAugmentation(), 8),
                    byteOrder, 8, Format.DEBUG_FRAME, "CIE reference outside section");
            }
            expectFailure(() -> OriginalFrameRanges.read(frame.bytes(), byteOrder, 8, Format.DEBUG_FRAME,
                -1, () -> false), "frame section address exceeds");
            require(OriginalFrameRanges.read(frame.bytes(), byteOrder, 8, Format.DEBUG_FRAME,
                Long.MAX_VALUE, () -> false).frames().getFirst().address() == 0x1000, "absolute FDE depends on section base");
            var augmented = fixture(false, byteOrder, 8, Format.EH_FRAME, 1, "zR", 0, 0x6000, 1);
            rejectedFrame(new Fixture(change(augmented, byteOrder, augmented.cieAugmentation(), 1, 2),
                augmented.fde(), augmented.pointer(), augmented.address(), augmented.size(),
                augmented.cieAugmentation(), augmented.fdeAugmentation(), augmented.idWidth()),
                byteOrder, 8, Format.EH_FRAME, "unexplained CIE augmentation bytes");
        }
        System.out.println("original-frame-parser-limits=PASS records=" + records + " bytes=" + (64 * 1024 * 1024));
    }

    private static void byteLimit(byte[] cie) throws Exception {
        // One CIE with padded initial instructions: the extent reader does not
        // interpret CFI. Keep the 64 MiB safety boundary in memory, not on disk.
        int bytes = 64 * 1024 * 1024;
        byte[] boundary = new byte[bytes];
        System.arraycopy(cie, 0, boundary, 0, cie.length);
        ByteBuffer.wrap(boundary).order(ByteOrder.LITTLE_ENDIAN).putInt(0, bytes - 4);
        var digest = java.security.MessageDigest.getInstance("SHA-256");
        byte[] original = digest.digest(boundary);
        Inventory accepted;
        try { accepted = read(boundary, ByteOrder.LITTLE_ENDIAN, 8, Format.EH_FRAME); }
        catch (IllegalArgumentException failure) { throw new AssertionError("byte limit rejected the supported boundary", failure); }
        require(accepted.cies() == 1 && accepted.frames().isEmpty(), "wrong inventory at byte limit");
        require(Arrays.equals(original, digest.digest(boundary)), "byte-limit scan modified input");
        byte[] excessive = Arrays.copyOf(boundary, bytes + 1);
        expectFailure(() -> read(excessive, ByteOrder.LITTLE_ENDIAN, 8, Format.EH_FRAME), "frame section size");
    }

    private static void expectFailure(Runnable action, String diagnostic) {
        try { action.run(); throw new AssertionError("accepted invalid frame: " + diagnostic); }
        catch (IllegalArgumentException failure) {
            require(failure.getMessage().contains(diagnostic), "unexpected frame rejection: " + failure);
        }
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
        augmentationEncodings();
        lebBoundaries();
        parserLimits();
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
        var overflow = fixture(false, order, 8, Format.DEBUG_FRAME, 4, "", 0, -1L, 2);
        reject(() -> read(overflow.bytes(), order, 8, Format.DEBUG_FRAME));
        var narrow = fixture(false, order, 4, Format.DEBUG_FRAME, 4, "", 0, 0xffff_ffffL, 2);
        reject(() -> read(narrow.bytes(), order, 4, Format.DEBUG_FRAME));
        var last = fixture(false, order, 4, Format.DEBUG_FRAME, 4, "", 0, 0xffff_ffffL, 1);
        require(read(last.bytes(), order, 4, Format.DEBUG_FRAME).frames().getFirst().address() == 0xffff_ffffL, "last ELF32 byte lost");
        require(read(new byte[0], order, 8, Format.DEBUG_FRAME).frames().isEmpty(), "empty section is not empty");
        System.out.println("original-frame-ranges-smoke=PASS checks=" + checks);
    }
}
