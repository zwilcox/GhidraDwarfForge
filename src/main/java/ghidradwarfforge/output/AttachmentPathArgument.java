package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** ASCII transport for literal paths through Windows Java's native-code-page launcher. */
final class AttachmentPathArgument {
    private static final int MAX_CHARACTERS = 16384;
    private static final int MAX_ENCODED_CHARACTERS = MAX_CHARACTERS * 4;

    private AttachmentPathArgument() { }

    static String encode(String path) throws IOException {
        check(path);
        try {
            ByteBuffer bytes = StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).encode(CharBuffer.wrap(path));
            byte[] copy = new byte[bytes.remaining()];
            bytes.get(copy);
            return Base64.getEncoder().encodeToString(copy);
        }
        catch (CharacterCodingException invalid) { throw new IOException("path is not valid Unicode", invalid); }
    }

    static String decode(String encoded) throws IOException {
        if (encoded == null || encoded.length() > MAX_ENCODED_CHARACTERS) {
            throw new IOException("encoded path exceeds the transport bound");
        }
        try {
            byte[] bytes = Base64.getDecoder().decode(encoded);
            if (!Base64.getEncoder().encodeToString(bytes).equals(encoded)) {
                throw new IOException("encoded path must use canonical Base64");
            }
            String path = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
            check(path);
            return path;
        }
        catch (IllegalArgumentException | CharacterCodingException invalid) {
            throw new IOException("encoded path is not canonical Base64 UTF-8", invalid);
        }
    }

    private static void check(String path) throws IOException {
        if (path == null || path.isEmpty() || path.length() > MAX_CHARACTERS || path.indexOf('\0') >= 0) {
            throw new IOException("path must be nonempty, bounded and contain no NUL");
        }
    }
}
