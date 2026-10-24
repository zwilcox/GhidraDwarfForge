package ghidradwarfforge.elf;

import java.nio.file.Path;
import java.util.Base64;
import java.util.HexFormat;

/** Read-only backend candidate evidence; this is not an attachment implementation. */
public final class DebuglinkToolProbe {
    public static void main(String[] args) throws Exception {
        if (args.length != 4) {
            throw new IllegalArgumentException("expected original candidate debug-file literal-basename-base64");
        }
        byte[] basename = Base64.getDecoder().decode(args[3]);
        var result = DebuglinkCandidateContent.observe(Path.of(args[0]), Path.of(args[1]),
            Path.of(args[2]), basename);
        require(result.programBytes().status() == ExecutableProgramBytes.Status.MATCHING_PROGRAM_BYTES,
            "program byte observation rejected candidate: " + result.programBytes());
        require(result.allocatedSections().status() == DebuglinkCandidateContent.AllocationStatus.MATCHING,
            "indexed executable allocation observation rejected candidate: " + result.allocatedSections());
        require(result.newDebuglink().status() == DebuglinkCandidateContent.DebuglinkStatus.MATCHING,
            "new debuglink observation rejected candidate: " + result.newDebuglink());
        System.out.println("declared-header-program-table-and-payloads=PASS (section-table header fields excepted)");
        System.out.println("indexed-executable-allocations=PASS");
        System.out.println("exact-new-debuglink=PASS");
        System.out.printf("debuglink-basename-hex=%s crc32=%08x bytes=%d%n",
            HexFormat.of().formatHex(basename), result.sidecarDigest().gnuDebuglinkCrc32(),
            result.sidecarDigest().byteCount());
        System.out.println("debuglink-tool-probe=PASS");
    }

    private static void require(boolean value, String message) {
        if (!value) {
            throw new AssertionError(message);
        }
    }
}
