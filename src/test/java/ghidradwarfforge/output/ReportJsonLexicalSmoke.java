package ghidradwarfforge.output;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Lexical admission and Reader contracts; full JSON/schema parsing stays separate. */
final class ReportJsonLexicalSmoke {
    private static int checks;

    private ReportJsonLexicalSmoke() { }

    static void check() throws Exception {
        checks = 0;
        var limits = new ReportJsonReader.Limits(4096, 128, 4, 32, 16, 32, 64);
        String[] accepted = {"null", "[0,12,null]", "{\"n\":null}", "\"nulla\"",
            "\"\u03bb\ud83d\ude00\"", "\"\\u03bb\\ud83d\\ude00\"", "\"a\\n\\t\\\\\\\"\"", "[[[0]]]"};
        String[] rejected = {"n", "nu", "nul", "nulx", "nulla", "nullnull", "Null", "nUll",
            "[", "{", "]", "}", "\"unfinished", "01", "12345678901", "\"\\ud800\"", "\"\\udc00\""};
        for (int bytes : new int[] {1, 2, 7}) {
            for (int characters : new int[] {1, 2, 7, 1024}) {
                for (String text : accepted) {
                    require(text.equals(valid(text.getBytes(StandardCharsets.UTF_8), bytes, characters, limits)),
                        "lexical reader changed valid characters: " + text);
                }
                for (String text : rejected) {
                    malformed(text.getBytes(StandardCharsets.UTF_8), bytes, characters, limits);
                }
                for (byte[] malformedUtf8 : new byte[][] {
                        {'"', (byte) 0xc0, (byte) 0xaf, '"'},
                        {'"', (byte) 0xe2, (byte) 0x82},
                        {'"', (byte) 0xed, (byte) 0xa0, (byte) 0x80, '"'}}) {
                    malformed(malformedUtf8, bytes, characters, limits);
                }
            }
        }
        byte[] unicode = "\"\u03bb\ud83d\ude00\"".getBytes(StandardCharsets.UTF_8);
        var exact = new ReportJsonReader.Limits(unicode.length, 3, 1, 1, 1, 1, 1);
        require(valid(unicode, 1, 1, exact).equals(new String(unicode, StandardCharsets.UTF_8)),
            "exact byte and UTF-16 limits rejected complete multibyte string");
        malformed(unicode, 1, 1, new ReportJsonReader.Limits(unicode.length - 1, 3, 1, 1, 1, 1, 1));
        malformed(unicode, 1, 1, new ReportJsonReader.Limits(unicode.length, 2, 1, 1, 1, 1, 1));
        malformed("[[0]]".getBytes(StandardCharsets.UTF_8), 1, 1,
            new ReportJsonReader.Limits(64, 3, 1, 1, 1, 1, 1));
        for (int field = 0; field < 7; field++) {
            for (int bad : new int[] {-1, 0}) {
                int[] values = {1, 1, 1, 1, 1, 1, 1};
                values[field] = bad;
                boolean refused = false;
                try {
                    new ReportJsonReader.Limits(values[0], values[1], values[2], values[3],
                        values[4], values[5], values[6]);
                }
                catch (IllegalArgumentException expected) {
                    refused = true;
                }
                require(refused, "nonpositive resource ceiling accepted at field " + field);
            }
        }
        System.out.println("report-json-lexical=PASS checks=" + checks + " byte-chunks=1,2,7 char-chunks=1,2,7,1024");
    }

    private static String valid(byte[] bytes, int byteChunk, int charChunk, ReportJsonReader.Limits limits) {
        try {
            return read(bytes, byteChunk, charChunk, limits);
        }
        catch (IOException invalid) {
            throw new AssertionError("valid lexical input or Reader operation rejected", invalid);
        }
    }

    private static String read(byte[] bytes, int byteChunk, int charChunk, ReportJsonReader.Limits limits)
            throws IOException {
        var input = new Chunked(bytes, byteChunk);
        try (var reader = new ReportJsonReader(input, () -> false, limits)) {
            char[] buffer = new char[charChunk + 2];
            Arrays.fill(buffer, '#');
            require(reader.read(buffer, 1, 0) == 0 && input.reads == 0, "empty read consumed input");
            require(Arrays.equals(buffer, "#".repeat(buffer.length).toCharArray()), "empty read changed destination");
            var result = new StringBuilder();
            int count;
            while ((count = reader.read(buffer, 1, charChunk)) != -1) {
                require(count > 0 && count <= charChunk && buffer[0] == '#' && buffer[buffer.length - 1] == '#',
                    "invalid returned count or write outside destination slice");
                result.append(buffer, 1, count);
            }
            int reads = input.reads;
            require(reader.read(buffer, 1, 0) == 0 && input.reads == reads, "empty EOF read touched stream");
            return result.toString();
        }
        finally {
            require(input.closed, "lexical reader did not close its owned input");
        }
    }

    private static void malformed(byte[] bytes, int byteChunk, int charChunk, ReportJsonReader.Limits limits)
            throws Exception {
        try {
            read(bytes, byteChunk, charChunk, limits);
        }
        catch (IOException expected) {
            return;
        }
        catch (RuntimeException wrong) {
            throw new AssertionError("malformed input escaped as an unchecked failure", wrong);
        }
        throw new AssertionError("invalid lexical input accepted: " + Arrays.toString(bytes));
    }

    private static final class Chunked extends ByteArrayInputStream {
        private final int chunk;
        private int reads;
        private boolean closed;

        Chunked(byte[] data, int chunk) {
            super(data);
            this.chunk = chunk;
        }

        @Override
        public synchronized int read(byte[] buffer, int offset, int length) {
            reads++;
            return super.read(buffer, offset, Math.min(length, chunk));
        }

        @Override
        public synchronized int read() {
            reads++;
            return super.read();
        }

        @Override
        public void close() throws IOException {
            closed = true;
            super.close();
        }
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
