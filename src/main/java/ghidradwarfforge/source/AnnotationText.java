package ghidradwarfforge.source;

import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/**
 * Reversible text for one physical line inside a synthetic C block comment.
 *
 * <p>Backslashes and control characters use JSON-compatible escapes. Delimiters,
 * trigraphs, format controls and isolated UTF-16 surrogates use hexadecimal
 * escapes. Printable Unicode is preserved without normalization. The caller
 * owns comment framing, line placement and the aggregate export budget; this
 * component never supplies an executable source address or truncates text.
 */
public final class AnnotationText {
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private AnnotationText() {
    }

    public static String encode(String value, int maxUtf8Bytes, BooleanSupplier cancelled) {
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(cancelled, "cancelled");
        if (maxUtf8Bytes < 0) throw new IllegalArgumentException("negative annotation text budget");
        checkCancelled(cancelled);
        var output = new StringBuilder(Math.min(value.length(), 256));
        int bytes = 0;
        for (int offset = 0; offset < value.length();) {
            checkCancelled(cancelled);
            int point = value.codePointAt(offset);
            int units = Character.charCount(point);
            String escaped = switch (point) {
                case '\\' -> "\\\\";
                case '\n' -> "\\n";
                case '\r' -> "\\r";
                case '\t' -> "\\t";
                case '\b' -> "\\b";
                case '\f' -> "\\f";
                default -> null;
            };
            boolean delimiter = point == '/' &&
                ((offset > 0 && value.charAt(offset - 1) == '*') ||
                    (offset + 1 < value.length() && value.charAt(offset + 1) == '*'));
            boolean trigraph = point == '?' && offset > 0 && value.charAt(offset - 1) == '?';
            boolean unsafe = Character.isISOControl(point) || Character.getType(point) == Character.FORMAT ||
                point == 0x2028 || point == 0x2029 || (point >= 0xd800 && point <= 0xdfff);
            if (escaped == null && (delimiter || trigraph || unsafe)) {
                var encoded = new StringBuilder(units * 6);
                for (int index = 0; index < units; index++) {
                    char unit = value.charAt(offset + index);
                    encoded.append('\\').append('u');
                    for (int shift = 12; shift >= 0; shift -= 4) encoded.append(HEX[(unit >>> shift) & 15]);
                }
                escaped = encoded.toString();
            }
            int required = escaped == null ? utf8Bytes(point) : escaped.length();
            if (required > maxUtf8Bytes - bytes) {
                throw new IllegalArgumentException("annotation text exceeds encoded UTF-8 budget of " + maxUtf8Bytes + " bytes");
            }
            bytes += required;
            if (escaped == null) output.appendCodePoint(point);
            else output.append(escaped);
            offset += units;
        }
        checkCancelled(cancelled);
        return output.toString();
    }

    private static int utf8Bytes(int point) {
        return point <= 0x7f ? 1 : point <= 0x7ff ? 2 : point <= 0xffff ? 3 : 4;
    }

    private static void checkCancelled(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("annotation text encoding cancelled");
    }
}
