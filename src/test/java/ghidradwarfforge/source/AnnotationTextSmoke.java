package ghidradwarfforge.source;

import com.google.gson.JsonParser;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

/** Independent JSON decoding and C-lexer corpus, including actual saved comments. */
public final class AnnotationTextSmoke {
    private static int checks;

    private AnnotationTextSmoke() {
    }

    private static String verify(String original) {
        String encoded = AnnotationText.encode(original, 1_000_000, () -> false);
        String decoded = JsonParser.parseString("\"" + encoded.replace("\"", "\\\"") + "\"").getAsString();
        if (!decoded.equals(original)) throw new AssertionError("annotation UTF-16 text changed");
        if (encoded.contains("*/") || encoded.contains("/*") || encoded.contains("??") ||
                encoded.codePoints().anyMatch(point -> Character.isISOControl(point) ||
                    Character.getType(point) == Character.FORMAT || point == 0x2028 || point == 0x2029)) {
            throw new AssertionError("unsafe physical comment line");
        }
        int bytes = encoded.getBytes(StandardCharsets.UTF_8).length;
        if (!AnnotationText.encode(original, bytes, () -> false).equals(encoded)) {
            throw new AssertionError("exact byte budget failed");
        }
        if (bytes > 0) {
            try {
                AnnotationText.encode(original, bytes - 1, () -> false);
                throw new AssertionError("under-budget annotation did not fail");
            }
            catch (IllegalArgumentException expected) {
                if (!expected.getMessage().contains("UTF-8 budget")) throw expected;
            }
        }
        checks++;
        return encoded;
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 0 && args.length != 2) throw new IllegalArgumentException("[saved-readback.json corpus.c]");
        if (!verify("*/ /* ??/\\\r\n\tλ").equals("*\\u002f \\u002f* ?\\u003f/\\\\\\r\\n\\tλ")) {
            throw new AssertionError("documented escape grammar changed");
        }
        verify("");
        verify("é e\u0301 😀 \ud800 \udfff \u202e \u2028 \u2029");
        var corpus = new StringBuilder("/* AnnotationText lexical corpus: no executable annotation rows. */\n");
        corpus.append("/* ").append(verify("*/\n#error annotation escaped\n/*")).append(" */\n");
        for (int point : new int[] {0x10000, 0x1f603, 0xe0001, 0xe007f, 0x10ffff}) {
            corpus.append("/* ").append(verify(new String(Character.toChars(point)))).append(" */\n");
        }
        for (int unit = 0; unit <= 0xffff; unit++) {
            corpus.append("/* ").append(verify("" + (char) unit)).append(" */\n");
        }
        for (String left : new String[] {"*", "/", "?", "\\", "\r", "\n", "\ud800", "\udfff"}) {
            for (String right : new String[] {"*", "/", "?", "\\", "\r", "\n", "\ud800", "\udfff"}) {
                corpus.append("/* ").append(verify(left + right + left)).append(" */\n");
            }
        }
        String cancellationText = "saved λ */ comment\\\r\n😀";
        var calls = new AtomicInteger();
        AnnotationText.encode(cancellationText, 1000, () -> { calls.incrementAndGet(); return false; });
        for (int point = 1; point <= calls.get(); point++) {
            int cancelAt = point;
            var observed = new AtomicInteger();
            try {
                AnnotationText.encode(cancellationText, 1000, () -> observed.incrementAndGet() == cancelAt);
                throw new AssertionError("cancellation checkpoint ignored: " + point);
            }
            catch (CancellationException expected) {
                if (observed.get() != cancelAt) throw new AssertionError("cancellation was delayed");
            }
        }
        int savedComments = 0;
        if (args.length == 2) {
            var saved = JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
            for (var row : saved.getAsJsonArray("comments")) {
                corpus.append("/* ").append(verify(row.getAsJsonObject().get("text").getAsString())).append(" */\n");
                savedComments++;
            }
            if (savedComments != 50) throw new AssertionError("saved fixture comments missing");
            corpus.append("int main(void) { return 0; }\n");
            Files.writeString(Path.of(args[1]), corpus.toString(), StandardCharsets.UTF_8);
        }
        System.out.println("annotation-text=PASS checks=" + checks + " cancellation-points=" + calls.get() +
            " saved-comments=" + savedComments);
    }
}
