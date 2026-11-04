package ghidradwarfforge.elf;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/**
 * Private validation view of a sectionless original, never a debug sidecar or
 * replacement target. Copies original bytes, disables the program-header table
 * and adds only null, table-proven .eh_frame and .shstrtab section entries.
 * The original program-table bytes remain inert in the copied prefix. No DWARF
 * is generated; this non-loadable view exists only for checking original frames.
 */
public final class OriginalFrameView {
    private static final byte[] NAMES = "\0.eh_frame\0.shstrtab\0".getBytes(StandardCharsets.US_ASCII);

    private OriginalFrameView() { }

    public static Path create(Path original, Path ownedParent, BooleanSupplier cancelled) throws IOException {
        check(cancelled);
        var image = ElfImage.read(original);
        if (!image.sections().isEmpty()) throw new IOException("original frame view requires a sectionless input");
        var frame = InheritedFrameBytes.discovered(image, cancelled);
        int width = image.is64Bit() ? 8 : 4;
        int entryBytes = image.is64Bit() ? 64 : 40;
        long tableOffset;
        long length;
        try {
            long unaligned = Math.addExact(image.fileSize(), NAMES.length);
            tableOffset = Math.addExact(unaligned, (width - unaligned % width) % width);
            length = Math.addExact(tableOffset, 3L * entryBytes);
        }
        catch (ArithmeticException invalid) { throw new IOException("original frame view layout overflows", invalid); }
        if (!image.is64Bit() && length > 0xffff_ffffL) throw new IOException("original frame view exceeds ELF32 offsets");
        byte[] header = image.headerBytes();
        var fields = ByteBuffer.wrap(header).order(image.byteOrder());
        if (image.is64Bit()) {
            fields.putLong(32, 0);
            fields.putLong(40, tableOffset);
        }
        else {
            fields.putInt(28, 0);
            fields.putInt(32, (int) tableOffset);
        }
        fields.putShort(image.is64Bit() ? 54 : 42, (short) 0);
        fields.putShort(image.is64Bit() ? 56 : 44, (short) 0);
        fields.putShort(image.is64Bit() ? 58 : 46, (short) entryBytes);
        fields.putShort(image.is64Bit() ? 60 : 48, (short) 3);
        fields.putShort(image.is64Bit() ? 62 : 50, (short) 2);
        Path directory = Files.createTempDirectory(ownedParent.toRealPath(), ".forge-original-frames-");
        Path view = directory.resolve("original-frame-view.elf");
        // A failure retains only this private view, never a final output name.
        try (var output = FileChannel.open(view, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            image.copyTo(output, cancelled);
            write(output, NAMES, cancelled);
            write(output, new byte[(int) (tableOffset - output.position())], cancelled);
            write(output, new byte[entryBytes], cancelled);
            write(output, section(image, 1, 1, frame.flags, frame.address, frame.offset, frame.size, 1), cancelled);
            write(output, section(image, 11, 3, 0, 0, image.fileSize(), NAMES.length, 1), cancelled);
            if (output.position() != length) throw new IOException("original frame view length differs from its plan");
            output.position(0);
            write(output, header, cancelled);
            output.force(true);
        }
        if (MatchedElfPrefix.compare(original, view, cancelled).status() !=
                MatchedElfPrefix.Status.MATCHING_COPIED_PREFIX) {
            throw new IOException("original frame view changed copied bytes; retained " + view);
        }
        InheritedFrameBytes.compare(original, view, cancelled);
        return view;
    }

    private static byte[] section(ElfImage image, int name, int type, long flags, long address,
            long offset, long size, long alignment) {
        var output = ByteBuffer.allocate(image.is64Bit() ? 64 : 40).order(image.byteOrder());
        output.putInt(name).putInt(type);
        if (image.is64Bit()) {
            output.putLong(flags).putLong(address).putLong(offset).putLong(size);
            output.putInt(0).putInt(0).putLong(alignment).putLong(0);
        }
        else {
            output.putInt((int) flags).putInt((int) address).putInt((int) offset).putInt((int) size);
            output.putInt(0).putInt(0).putInt((int) alignment).putInt(0);
        }
        return output.array();
    }

    private static void write(FileChannel output, byte[] bytes, BooleanSupplier cancelled) throws IOException {
        var buffer = ByteBuffer.wrap(bytes);
        while (buffer.hasRemaining()) {
            check(cancelled);
            if (output.write(buffer) <= 0) throw new IOException("original frame view write made no progress");
        }
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("original frame view cancelled");
    }
}
