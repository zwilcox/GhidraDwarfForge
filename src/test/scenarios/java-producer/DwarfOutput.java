package evaluation;

import java.io.ByteArrayOutputStream;
import java.nio.ByteOrder;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/** The evaluation emits DWARF32 units for either ELF address width. */
final class DwarfOutput extends ByteArrayOutputStream {
    private final int addressBytes;
    private final ByteOrder order;

    DwarfOutput(int addressBytes, ByteOrder order) {
        if (addressBytes != 4 && addressBytes != 8) {
            throw new IllegalArgumentException("target address size must be 4 or 8");
        }
        this.addressBytes = addressBytes;
        this.order = Objects.requireNonNull(order);
    }

    void address(long bits) {
        fixed(bits, addressBytes);
    }

    void offset(long offset) {
        fixed(offset, 4);
    }

    void unitLength(long length) {
        if (length < 0 || length >= 0xfffffff0L) {
            throw new IllegalArgumentException("unrepresentable DWARF32 initial length");
        }
        fixed(length, 4);
    }

    void fixed(long bits, int width) {
        if (width != 1 && width != 2 && width != 4 && width != 8) {
            throw new IllegalArgumentException("unsupported fixed-width operand");
        }
        if (width != 8 && bits >>> (width * 8) != 0) {
            throw new IllegalArgumentException("value does not fit in " + width + " bytes");
        }
        for (int index = 0; index < width; index++) {
            int significance = order == ByteOrder.LITTLE_ENDIAN ? index : width - index - 1;
            write((int) (bits >>> (significance * 8)));
        }
    }

    void uleb(long bits) {
        do {
            int chunk = (int) (bits & 0x7f);
            bits >>>= 7;
            write(bits == 0 ? chunk : chunk | 0x80);
        } while (bits != 0);
    }

    void sleb(long value) {
        while (true) {
            int chunk = (int) (value & 0x7f);
            value >>= 7;
            boolean sign = (chunk & 0x40) != 0;
            if ((value == 0 && !sign) || (value == -1 && sign)) {
                write(chunk);
                return;
            }
            write(chunk | 0x80);
        }
    }

    static byte[] stringBytes(String value) {
        if (value.indexOf('\0') >= 0) {
            throw new IllegalArgumentException("embedded NUL in DWARF string");
        }
        try {
            var encoded = StandardCharsets.UTF_8.newEncoder().encode(CharBuffer.wrap(value));
            byte[] bytes = new byte[encoded.remaining()];
            encoded.get(bytes);
            return bytes;
        }
        catch (CharacterCodingException error) {
            throw new IllegalArgumentException("invalid Unicode in DWARF string", error);
        }
    }
}
