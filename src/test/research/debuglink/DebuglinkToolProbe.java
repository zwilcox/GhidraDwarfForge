package ghidradwarfforge.elf;

import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.zip.CRC32;

/** Read-only, small-fixture backend evidence; this is not an attachment implementation. */
public final class DebuglinkToolProbe {
    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            throw new IllegalArgumentException("expected original candidate debug-file");
        }
        ElfImage original = ElfImage.read(Path.of(args[0]));
        ElfImage candidate = ElfImage.read(Path.of(args[1]));
        byte[] before = original.bytes();
        byte[] after = candidate.bytes();
        require(original.is64Bit() == candidate.is64Bit() &&
            original.byteOrder() == candidate.byteOrder(), "class/byte order changed");
        byte[] beforeHeader = original.headerBytes();
        byte[] afterHeader = candidate.headerBytes();
        for (int offset = 0; offset < beforeHeader.length; offset++) {
            require(sectionTableField(original.is64Bit(), offset) ||
                beforeHeader[offset] == afterHeader[offset], "non-section ELF header changed");
        }
        ByteBuffer header = ByteBuffer.wrap(beforeHeader).order(original.byteOrder());
        long phoff = original.is64Bit() ? header.getLong(32) : Integer.toUnsignedLong(header.getInt(28));
        int phsize = Short.toUnsignedInt(header.getShort(original.is64Bit() ? 54 : 42));
        require(original.segments().size() == candidate.segments().size(), "program count changed");
        require(Arrays.equals(Arrays.copyOfRange(before, (int) phoff,
            (int) phoff + phsize * original.segments().size()),
            Arrays.copyOfRange(after, (int) phoff,
                (int) phoff + phsize * original.segments().size())), "program table changed");
        for (ElfImage.Segment segment : original.segments()) {
            if (segment.type != 1) {
                continue;
            }
            for (long offset = segment.offset; offset < segment.offset + segment.fileSize; offset++) {
                require(offset < after.length, "loaded bytes truncated");
                require(sectionTableField(original.is64Bit(), offset) ||
                    before[(int) offset] == after[(int) offset], "loaded byte changed at " + offset);
            }
        }
        var links = candidate.sections().stream()
            .filter(section -> section.name().equals(".gnu_debuglink")).toList();
        require(links.size() == 1, "expected exactly one debuglink section");
        ElfImage.Section link = links.get(0);
        require(link.type == 1 && link.flags == 0, "debuglink is not nonallocated PROGBITS");
        byte[] data = candidate.sectionData(link);
        int end = 0;
        while (end < data.length && data[end] != 0) {
            end++;
        }
        String name = new String(data, 0, end, java.nio.charset.StandardCharsets.UTF_8);
        require(name.equals(Path.of(args[2]).getFileName().toString()), "debuglink basename mismatch");
        int crcOffset = (end + 1 + 3) & ~3;
        require(data.length == crcOffset + 4, "debuglink padding/CRC length mismatch");
        for (int offset = end; offset < crcOffset; offset++) {
            require(data[offset] == 0, "nonzero debuglink padding");
        }
        CRC32 crc = new CRC32();
        crc.update(Files.readAllBytes(Path.of(args[2])));
        require(Integer.toUnsignedLong(ByteBuffer.wrap(data).order(candidate.byteOrder())
            .getInt(crcOffset)) == crc.getValue(), "target-endian CRC mismatch");
        System.out.println("program-headers-and-load-bytes=PASS (section-table ELF header fields excepted)");
        System.out.printf("debuglink-basename=%s crc32=%08x endian=%s%n", name,
            crc.getValue(), candidate.byteOrder());
        System.out.println("debuglink-tool-probe=PASS");
    }

    private static boolean sectionTableField(boolean elf64, long offset) {
        return elf64 ? offset >= 40 && offset < 48 || offset >= 58 && offset < 64
                : offset >= 32 && offset < 36 || offset >= 46 && offset < 52;
    }

    private static void require(boolean value, String message) {
        if (!value) {
            throw new AssertionError(message);
        }
    }
}
