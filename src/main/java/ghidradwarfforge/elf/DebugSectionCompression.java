package ghidradwarfforge.elf;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;
import java.util.zip.Deflater;

/** Optional gABI section compression; DWARF offsets always refer to plain bytes. */
public enum DebugSectionCompression {
    NONE,
    ZLIB;

    private static final int CHUNK_BYTES = 32 * 1024;

    record Stored(byte[] bytes, boolean compressed, int alignment) { }

    public static DebugSectionCompression parse(String name) {
        return switch (Objects.requireNonNull(name, "compression")) {
            case "none" -> NONE;
            case "zlib" -> ZLIB;
            default -> throw new IllegalArgumentException(
                "unsupported debug-section compression: " + name + " (expected none or zlib)");
        };
    }

    Stored encode(byte[] plain, boolean wide, ByteOrder order, BooleanSupplier cancelled) {
        return encode(plain, wide, order, 1, cancelled);
    }

    Stored encode(byte[] plain, boolean wide, ByteOrder order, int plainAlignment, BooleanSupplier cancelled) {
        Objects.requireNonNull(plain, "plain");
        Objects.requireNonNull(order, "order");
        Objects.requireNonNull(cancelled, "cancelled");
        if (plainAlignment <= 0 || (plainAlignment & (plainAlignment - 1)) != 0 || plainAlignment > 8) {
            throw new IllegalArgumentException("unsupported plain debug-section alignment");
        }
        checkCancelled(cancelled);
        int headerSize = wide ? 24 : 12;
        if (this == NONE || plain.length <= headerSize) {
            return new Stored(plain, false, plainAlignment);
        }
        // Input and output chunks bound each native deflate call. Compression
        // stops once its header/payload cannot be smaller than the original;
        // temporary output therefore remains bounded by the input section size.
        Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, false);
        try {
            ByteArrayOutputStream compressed = new ByteArrayOutputStream(Math.min(4096, plain.length));
            byte[] buffer = new byte[CHUNK_BYTES];
            int supplied = 0;
            while (!deflater.finished()) {
                checkCancelled(cancelled);
                if (deflater.needsInput() && supplied < plain.length) {
                    int count = Math.min(CHUNK_BYTES, plain.length - supplied);
                    deflater.setInput(plain, supplied, count);
                    supplied += count;
                    if (supplied == plain.length) {
                        deflater.finish();
                    }
                }
                int count = deflater.deflate(buffer);
                if (count >= plain.length - headerSize - compressed.size()) {
                    return new Stored(plain, false, plainAlignment);
                }
                compressed.write(buffer, 0, count);
                if (count == 0 && !deflater.finished() && !deflater.needsInput()) {
                    throw new IllegalStateException("debug-section compression made no progress");
                }
            }
            checkCancelled(cancelled);
            ByteBuffer result = ByteBuffer.allocate(headerSize + compressed.size()).order(order);
            result.putInt(1); // ELFCOMPRESS_ZLIB, with a normal zlib stream (not raw deflate).
            if (wide) {
                result.putInt(0); // Elf64_Chdr.ch_reserved
                result.putLong(plain.length);
                result.putLong(plainAlignment);
            }
            else {
                result.putInt(plain.length);
                result.putInt(plainAlignment);
            }
            result.put(compressed.toByteArray());
            return new Stored(result.array(), true, wide ? 8 : 4);
        }
        finally {
            deflater.end();
        }
    }

    private static void checkCancelled(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) {
            throw new CancellationException("debug-section compression cancelled");
        }
    }
}
