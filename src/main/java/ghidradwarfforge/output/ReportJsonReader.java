package ghidradwarfforge.output;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/**
 * Bounded lexical guard for the current report schema, not a JSON parser.
 * Gson handles document grammar. Its supplied 2.9 reader accepts some invalid
 * string escapes/controls, unpaired surrogates, mixed-case null and an initial
 * BOM even in nonlenient mode; reject these before delivering characters.
 * The current schema has only nonnegative integers and null outside strings.
 */
final class ReportJsonReader extends Reader {
    static final Limits DEFAULT_LIMITS = new Limits(64L * 1024 * 1024, 65536, 8,
        1_000_000, 250_000);

    /** Package-private smaller budgets support boundary tests without public policy knobs. */
    record Limits(long bytes, int stringUnits, int depth, int values, int arrayItems) {
        Limits {
            if (bytes < 1 || stringUnits < 1 || depth < 1 || values < 1 || arrayItems < 1) {
                throw new IllegalArgumentException("report reader limits must be positive");
            }
        }
    }

    private enum BareToken { NONE, INTEGER, NULL }

    private final Reader input;
    private final BooleanSupplier cancelled;
    private final Limits limits;
    private boolean inString;
    private boolean escaped;
    private boolean highSurrogate;
    private boolean leadingZero;
    private int unicodeDigits;
    private int unicodeValue;
    private int stringUnits;
    private int depth;
    private BareToken bareToken = BareToken.NONE;
    private int bareLength;

    /** Owns the successfully supplied stream, closed through this reader. */
    ReportJsonReader(InputStream input, BooleanSupplier cancelled, Limits limits) {
        this.input = new InputStreamReader(new BoundedInput(input, limits.bytes()),
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT));
        this.cancelled = cancelled;
        this.limits = limits;
    }

    @Override
    public int read(char[] buffer, int offset, int length) throws IOException {
        java.util.Objects.checkFromIndexSize(offset, length, buffer.length);
        checkCancelled(cancelled);
        if (length == 0) {
            return 0;
        }
        int count = input.read(buffer, offset, Math.min(length, 1024));
        checkCancelled(cancelled);
        if (count == -1) {
            finishBareToken();
            if (inString || depth != 0) {
                throw invalid("unfinished string or container");
            }
            return -1;
        }
        if (count <= 0) {
            throw invalid("input stopped making progress");
        }
        // Check before Gson sees this bounded chunk and grows any token buffer.
        for (int index = offset; index < offset + count; index++) {
            checkCancelled(cancelled);
            accept(buffer[index]);
        }
        return count;
    }

    private void accept(char character) throws IOException {
        if (inString) {
            acceptStringCharacter(character);
            return;
        }
        if (bareToken != BareToken.NONE) {
            if (bareToken == BareToken.INTEGER && character >= '0' && character <= '9') {
                if (leadingZero || ++bareLength > 10) {
                    throw invalid("noncanonical or oversized integer");
                }
                return;
            }
            if (bareToken == BareToken.NULL && character >= 'a' && character <= 'z') {
                if (bareLength >= 4 || character != "null".charAt(bareLength++)) {
                    throw invalid("invalid null literal");
                }
                return;
            }
            finishBareToken();
        }
        if (character == '"') {
            inString = true;
            stringUnits = 0;
            highSurrogate = false;
        }
        else if (character >= '0' && character <= '9') {
            bareToken = BareToken.INTEGER;
            bareLength = 1;
            leadingZero = character == '0';
        }
        else if (character == 'n') {
            bareToken = BareToken.NULL;
            bareLength = 1;
        }
        else {
            switch (character) {
                case '{', '[' -> {
                    if (++depth > limits.depth()) {
                        throw invalid("nesting exceeds safety limit " + limits.depth());
                    }
                }
                case '}', ']' -> {
                    if (--depth < 0) {
                        throw invalid("unmatched closing container");
                    }
                }
                case ' ', '\t', '\r', '\n', ':', ',' -> { }
                default -> throw invalid("invalid character outside a report string");
            }
        }
    }

    private void acceptStringCharacter(char character) throws IOException {
        if (unicodeDigits > 0) {
            int digit = Character.digit(character, 16);
            if (digit < 0 || character > 127) {
                throw invalid("invalid Unicode escape");
            }
            unicodeValue = unicodeValue * 16 + digit;
            if (--unicodeDigits == 0) {
                decodedUnit((char) unicodeValue);
            }
        }
        else if (escaped) {
            escaped = false;
            switch (character) {
                case 'u' -> {
                    unicodeDigits = 4;
                    unicodeValue = 0;
                }
                case '"', '\\', '/' -> decodedUnit(character);
                case 'b' -> decodedUnit('\b');
                case 'f' -> decodedUnit('\f');
                case 'n' -> decodedUnit('\n');
                case 'r' -> decodedUnit('\r');
                case 't' -> decodedUnit('\t');
                default -> throw invalid("invalid string escape");
            }
        }
        else if (character == '"') {
            if (highSurrogate) {
                throw invalid("unpaired high surrogate");
            }
            inString = false;
        }
        else if (character == '\\') {
            escaped = true;
        }
        else {
            if (character < 0x20) {
                throw invalid("unescaped string control character");
            }
            decodedUnit(character);
        }
    }

    private void decodedUnit(char character) throws IOException {
        if (++stringUnits > limits.stringUnits()) {
            throw invalid("string exceeds safety limit " + limits.stringUnits() + " UTF-16 units");
        }
        if (highSurrogate) {
            if (!Character.isLowSurrogate(character)) {
                throw invalid("unpaired high surrogate");
            }
            highSurrogate = false;
        }
        else if (Character.isHighSurrogate(character)) {
            highSurrogate = true;
        }
        else if (Character.isLowSurrogate(character)) {
            throw invalid("unpaired low surrogate");
        }
    }

    private void finishBareToken() throws IOException {
        if (bareToken == BareToken.NULL && bareLength != 4) {
            throw invalid("incomplete null literal");
        }
        bareToken = BareToken.NONE;
        bareLength = 0;
    }

    static void checkCancelled(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) {
            throw new CancellationException("export report reading cancelled");
        }
    }

    private static IOException invalid(String detail) {
        return new IOException("invalid or unsupported report JSON: " + detail);
    }

    @Override
    public void close() throws IOException {
        input.close();
    }

    private static final class BoundedInput extends InputStream {
        private final InputStream input;
        private final long limit;
        private long count;

        private BoundedInput(InputStream input, long limit) {
            this.input = input;
            this.limit = limit;
        }

        @Override
        public int read(byte[] buffer, int offset, int length) throws IOException {
            java.util.Objects.checkFromIndexSize(offset, length, buffer.length);
            if (length == 0) {
                return 0;
            }
            if (count == limit) {
                // One extra byte distinguishes exact-limit EOF from over-limit
                // input; it is never delivered to the decoder or accumulated.
                if (input.read() != -1) {
                    throw invalid("input exceeds safety limit " + limit + " bytes");
                }
                return -1;
            }
            int requested = (int) Math.min(length, limit - count);
            int read = input.read(buffer, offset, requested);
            if (read < -1 || read == 0 || read > requested) {
                throw invalid("input made no progress or returned an invalid count");
            }
            if (read > 0) {
                count += read; // Bounded above by the positive, fixed limit.
            }
            return read;
        }

        @Override
        public int read() throws IOException {
            byte[] single = new byte[1];
            return read(single, 0, 1) == -1 ? -1 : Byte.toUnsignedInt(single[0]);
        }

        @Override
        public void close() throws IOException {
            input.close();
        }
    }
}
