package ghidradwarfforge.elf;

import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.CRC32;

/** Read-only, small-fixture backend evidence; this is not an attachment implementation. */
public final class DebuglinkToolProbe {
    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            throw new IllegalArgumentException("expected original candidate debug-file");
        }
        var programBytes = ExecutableProgramBytes.compare(Path.of(args[0]), Path.of(args[1]));
        require(programBytes.status() == ExecutableProgramBytes.Status.MATCHING_PROGRAM_BYTES,
            "program byte observation rejected candidate: " + programBytes);
        ElfImage candidate = ElfImage.read(Path.of(args[1]));
        // This separate small-fixture check concerns only the literal association;
        // program-byte agreement does not imply a valid debuglink or debug artifact.
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
        System.out.println("declared-header-program-table-and-payloads=PASS (section-table header fields excepted)");
        System.out.printf("debuglink-basename=%s crc32=%08x endian=%s%n", name,
            crc.getValue(), candidate.byteOrder());
        System.out.println("debuglink-tool-probe=PASS");
    }

    private static void require(boolean value, String message) {
        if (!value) {
            throw new AssertionError(message);
        }
    }
}
