package ghidradwarfforge.output;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

/** Native-free byte, cancellation and resource-ownership checks. */
public final class FileDigestsSmoke {
    private static final Path UNOPENED = Path.of("unopened/parent/../digest-input");
    private static final String EMPTY_SHA256 =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    private FileDigestsSmoke() {
    }

    public static void main(String[] args) throws Exception {
        knownVectors();
        bufferBoundaries();
        cancellation();
        failures();
        resultBounds();
        System.out.println("file-digests-smoke=PASS");
    }

    private static void knownVectors() throws Exception {
        vector("", EMPTY_SHA256, 0);
        vector("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            0x3524_41c2L);
        vector("123456789", "15e2b0d3c33891ebb0f1ef609ec419420c20e320ce94c65fbc8c3312448eb225",
            0xcbf4_3926L);
    }

    private static void vector(String text, String sha256, long crc) throws Exception {
        byte[] bytes = text.getBytes(StandardCharsets.US_ASCII);
        TrackingInput stream = new TrackingInput(bytes, 2);
        FileDigests.Result result = read(stream);
        require(result.equals(new FileDigests.Result(sha256, crc, bytes.length)),
            "known SHA/CRC vector mismatch");
        require(bitwiseCrc(bytes) == crc, "independent CRC vector mismatch");
        require(stream.closes == 1 && stream.eof, "successful read did not close at EOF");
    }

    private static void bufferBoundaries() throws Exception {
        Path file = Files.createTempFile("forge-file-digests-", ".bytes");
        try {
            for (int size : new int[] { 0, 1, 31, 65535, 65536, 65537, 196619 }) {
                byte[] bytes = new byte[size];
                for (int index = 0; index < size; index++) {
                    bytes[index] = (byte) (index * 37 + 11);
                }
                FileDigests.Result expected = new FileDigests.Result(
                    HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)),
                    bitwiseCrc(bytes), size);
                Files.write(file, bytes);
                var modified = Files.getLastModifiedTime(file);
                require(FileDigests.read(file).equals(expected) &&
                    FileDigests.read(file, () -> false).equals(expected),
                    "file digest mismatch at buffer boundary " + size);
                require(Arrays.equals(Files.readAllBytes(file), bytes) &&
                    Files.getLastModifiedTime(file).equals(modified),
                    "digest modified its input");
                for (int chunk : new int[] { 1, 7, 65536 }) {
                    TrackingInput stream = new TrackingInput(bytes, chunk);
                    require(read(stream).equals(expected), "short-read digest mismatch");
                    require(stream.closes == 1 && stream.eof && stream.largestRequest == 65536,
                        "read ownership or buffer bound mismatch");
                }
            }
        }
        finally {
            Files.delete(file);
        }
    }

    private static void cancellation() throws Exception {
        AtomicInteger opens = new AtomicInteger();
        expect(CancellationException.class, () -> FileDigests.read(UNOPENED, () -> true,
            path -> { opens.incrementAndGet(); throw new AssertionError("cancelled input opened"); }));
        require(opens.get() == 0, "cancel-before-open called the opener");
        Path absent = Files.createTempDirectory("forge-digest-cancel-");
        try {
            expect(CancellationException.class,
                () -> FileDigests.read(absent.resolve("missing"), () -> true));
            try (var entries = Files.list(absent)) {
                require(entries.count() == 0, "cancel-before-open created an output");
            }
        }
        finally {
            Files.delete(absent);
        }

        TrackingInput between = new TrackingInput(new byte[15], 4);
        expect(CancellationException.class, () -> FileDigests.read(UNOPENED,
            () -> between.reads == 1, path -> between));
        require(between.reads == 1 && between.position == 4 && between.closes == 1,
            "between-read cancellation returned data, read further, or leaked the stream");

        TrackingInput atEof = new TrackingInput(new byte[] { 1, 2, 3 }, 2);
        expect(CancellationException.class, () -> FileDigests.read(UNOPENED,
            () -> atEof.eof, path -> atEof));
        require(atEof.eof && atEof.position == 3 && atEof.closes == 1,
            "EOF cancellation leaked the stream");

        TrackingInput callback = new TrackingInput(new byte[15], 4);
        IllegalStateException callbackFailure = new IllegalStateException("injected callback failure");
        require(expect(IllegalStateException.class, () -> FileDigests.read(UNOPENED,
            () -> { if (callback.reads != 0) { throw callbackFailure; } return false; },
            path -> callback)) == callbackFailure, "callback failure was replaced");
        require(callback.closes == 1 && callback.reads == 1,
            "callback failure leaked input or continued reading");

        TrackingInput cancelAndClose = new TrackingInput(new byte[15], 4);
        cancelAndClose.closeFailure = new IOException("injected cancel-close failure");
        CancellationException cancelled = expect(CancellationException.class,
            () -> FileDigests.read(UNOPENED, () -> cancelAndClose.reads == 1,
                path -> cancelAndClose));
        require(cancelled.getSuppressed().length == 1 &&
            cancelled.getSuppressed()[0] == cancelAndClose.closeFailure && cancelAndClose.closes == 1,
            "close failure hid cancellation or was lost");
    }

    private static void failures() throws Exception {
        IOException opening = new IOException("injected opening failure");
        require(expect(IOException.class,
            () -> FileDigests.read(UNOPENED, () -> false, path -> { throw opening; })) == opening,
            "opening failure was replaced");

        TrackingInput reading = new TrackingInput(new byte[15], 4);
        reading.readFailure = new IOException("injected reading failure");
        reading.failRead = 2;
        require(expect(IOException.class, () -> read(reading)) == reading.readFailure,
            "reading failure was replaced");
        require(reading.reads == 2 && reading.position == 4 && reading.closes == 1,
            "failed read continued or leaked input");

        TrackingInput closing = new TrackingInput(new byte[15], 4);
        closing.closeFailure = new IOException("injected closing failure");
        require(expect(IOException.class, () -> read(closing)) == closing.closeFailure &&
            closing.eof && closing.closes == 1, "close failure returned a successful digest");

        TrackingInput both = new TrackingInput(new byte[15], 4);
        both.readFailure = new IOException("injected primary read failure");
        both.closeFailure = new IOException("injected secondary close failure");
        both.failRead = 2;
        IOException failure = expect(IOException.class, () -> read(both));
        require(failure == both.readFailure && failure.getSuppressed().length == 1 &&
            failure.getSuppressed()[0] == both.closeFailure && both.closes == 1,
            "read/close exception ordering was not retained");

        for (int readNumber : new int[] { 1, 2 }) {
            TrackingInput zero = new TrackingInput(new byte[15], 4);
            zero.zeroRead = readNumber;
            expect(IOException.class, () -> read(zero));
            require(zero.reads == readNumber && zero.closes == 1,
                "zero-progress input spun or leaked");
        }
        expect(NullPointerException.class, () -> FileDigests.read(null));
        expect(NullPointerException.class, () -> FileDigests.read(UNOPENED, null));
    }

    private static void resultBounds() throws Exception {
        require(new FileDigests.Result(EMPTY_SHA256, 0xffff_ffffL, 1L << 32).byteCount() == 1L << 32,
            "result narrowed the unsigned CRC or long byte count");
        expect(IllegalArgumentException.class, () -> new FileDigests.Result("bad", 0, 0));
        expect(IllegalArgumentException.class, () -> new FileDigests.Result(EMPTY_SHA256, -1, 0));
        expect(IllegalArgumentException.class,
            () -> new FileDigests.Result(EMPTY_SHA256, 0x1_0000_0000L, 0));
        expect(IllegalArgumentException.class, () -> new FileDigests.Result(EMPTY_SHA256, 0, -1));
    }

    private static FileDigests.Result read(TrackingInput stream) throws IOException {
        return FileDigests.read(UNOPENED, () -> false, path -> {
            require(path == UNOPENED, "digest rewrote the supplied path before opening");
            return stream;
        });
    }

    /** Independent reflected polynomial calculation; does not use java.util.zip. */
    private static long bitwiseCrc(byte[] bytes) {
        int remainder = -1;
        for (byte value : bytes) {
            remainder ^= Byte.toUnsignedInt(value);
            for (int bit = 0; bit < 8; bit++) {
                remainder = (remainder >>> 1) ^ ((remainder & 1) == 0 ? 0 : 0xedb8_8320);
            }
        }
        return Integer.toUnsignedLong(~remainder);
    }

    private static final class TrackingInput extends InputStream {
        private final byte[] bytes;
        private final int chunk;
        private int position;
        private int reads;
        private int closes;
        private int largestRequest;
        private boolean eof;
        private int failRead;
        private int zeroRead;
        private IOException readFailure;
        private IOException closeFailure;

        private TrackingInput(byte[] bytes, int chunk) {
            this.bytes = bytes;
            this.chunk = chunk;
        }

        @Override
        public int read() {
            throw new AssertionError("digest unexpectedly used individual reads");
        }

        @Override
        public int read(byte[] destination, int offset, int length) throws IOException {
            reads++;
            largestRequest = Math.max(largestRequest, length);
            if (reads == failRead) {
                throw readFailure;
            }
            if (reads == zeroRead) {
                return 0;
            }
            if (position == bytes.length) {
                eof = true;
                return -1;
            }
            int count = Math.min(Math.min(chunk, length), bytes.length - position);
            System.arraycopy(bytes, position, destination, offset, count);
            position += count;
            return count;
        }

        @Override
        public void close() throws IOException {
            closes++;
            if (closeFailure != null) {
                throw closeFailure;
            }
        }
    }

    private static <T extends Throwable> T expect(Class<T> type, Action action) throws Exception {
        try {
            action.run();
        }
        catch (Throwable failure) {
            if (type.isInstance(failure)) {
                return type.cast(failure);
            }
            throw new AssertionError("unexpected failure type, expected " + type.getName(), failure);
        }
        throw new AssertionError("expected " + type.getName());
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    @FunctionalInterface
    private interface Action {
        void run() throws Exception;
    }
}
