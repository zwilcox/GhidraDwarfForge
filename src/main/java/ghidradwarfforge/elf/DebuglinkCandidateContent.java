package ghidradwarfforge.elf;

import ghidradwarfforge.output.FileDigests;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/**
 * Read-only content checks for an explicitly selected initial debuglink candidate.
 * Program bytes, indexed executable allocations and the exact GNU creation
 * record remain separate observations, with no aggregate approval. This does
 * not establish receipt/ELF identity, valid DWARF, runtime equivalence, host
 * metadata, safe replacement, a snapshot or attachment readiness. Ordinary
 * export is unchanged; no backend is launched and no selected file is modified.
 *
 * Basename bytes are supplied literally, not inferred from a Java path or
 * decoded as UTF-8. Their host/backend encoding is the caller's responsibility.
 * All three regular-file preconditions precede blocking reads; they do not
 * prevent replacement races. Alias/leaf-link traversal follows the actual host.
 * Observations are sequential and source-change checks are only best effort.
 *
 * ElfImage's bounds and signed offsets apply. Raw names independently enforce
 * 64 KiB per used slice and 16 MiB per table/aggregate; link data is at most
 * 65544 bytes. Program coverage is sorted/merged once, then searched by index.
 * Existing readers own/close all channels. Cancellation surrounds reads and
 * bounded walks, but cannot interrupt a blocked call or every parser operation.
 * Maximum metadata combinations are not promised to fit a 64 MiB heap.
 */
public final class DebuglinkCandidateContent {
    private static final int MAX_BASENAME_BYTES = 65536;
    private static final byte[] LINK_NAME = ".gnu_debuglink".getBytes(StandardCharsets.US_ASCII);

    public enum AllocationStatus { MATCHING, DIFFERENT, UNSUPPORTED, NO_ALLOCATION_EVIDENCE }
    public enum DebuglinkStatus { MATCHING, DIFFERENT, UNSUPPORTED }

    /** -1 means there is no corresponding physical section index. */
    public record Issue(int originalIndex, int candidateIndex, String field,
            String expected, String observed) {
        public Issue {
            if (originalIndex < -1 || candidateIndex < -1) {
                throw new IllegalArgumentException("invalid section index");
            }
            requireText(field, "field");
            requireText(expected, "expected");
            requireText(observed, "observed");
        }
    }

    public record AllocationObservation(AllocationStatus status, Optional<Issue> issue,
            String diagnostic) {
        public AllocationObservation {
            Objects.requireNonNull(status, "status");
            validateIssue(status == AllocationStatus.DIFFERENT || status == AllocationStatus.UNSUPPORTED,
                issue, diagnostic);
        }
    }

    public record DebuglinkObservation(DebuglinkStatus status, Optional<Issue> issue,
            String diagnostic) {
        public DebuglinkObservation {
            Objects.requireNonNull(status, "status");
            validateIssue(status != DebuglinkStatus.MATCHING, issue, diagnostic);
        }
    }

    public record Result(ExecutableProgramBytes.Result programBytes,
            AllocationObservation allocatedSections, DebuglinkObservation newDebuglink,
            FileDigests.Result sidecarDigest) {
        public Result {
            Objects.requireNonNull(programBytes, "programBytes");
            Objects.requireNonNull(allocatedSections, "allocatedSections");
            Objects.requireNonNull(newDebuglink, "newDebuglink");
            Objects.requireNonNull(sidecarDigest, "sidecarDigest");
        }
    }

    private DebuglinkCandidateContent() {
    }

    public static Result observe(Path original, Path candidate, Path sidecar, byte[] expectedBasename)
            throws IOException {
        return observe(original, candidate, sidecar, expectedBasename, () -> false);
    }

    public static Result observe(Path original, Path candidate, Path sidecar,
            byte[] expectedBasename, BooleanSupplier cancelled) throws IOException {
        Objects.requireNonNull(original, "original");
        Objects.requireNonNull(candidate, "candidate");
        Objects.requireNonNull(sidecar, "sidecar");
        Objects.requireNonNull(cancelled, "cancelled");
        byte[] basename = basename(expectedBasename);
        checkCancelled(cancelled);
        BasicFileAttributes originalState = attributes(original);
        checkCancelled(cancelled);
        BasicFileAttributes candidateState = attributes(candidate);
        checkCancelled(cancelled);
        BasicFileAttributes sidecarState = attributes(sidecar);
        ElfImage before = read(original, cancelled);
        ElfImage after = read(candidate, cancelled);
        var program = ExecutableProgramBytes.compare(original, candidate, cancelled);
        var digest = FileDigests.read(sidecar, cancelled);
        Names originalNames = new Names(before, cancelled);
        Names candidateNames = new Names(after, cancelled);
        AllocationObservation allocations = allocations(before, after, originalNames, candidateNames, cancelled);
        DebuglinkObservation link = link(before, after, originalNames, candidateNames, basename,
            digest.gnuDebuglinkCrc32(), cancelled);
        unchanged(original, originalState);
        unchanged(candidate, candidateState);
        unchanged(sidecar, sidecarState);
        checkCancelled(cancelled);
        return new Result(program, allocations, link, digest);
    }

    private static AllocationObservation allocations(ElfImage before, ElfImage after,
            Names a, Names b, BooleanSupplier cancelled) throws IOException {
        if (!canonicalNamed(before) || !canonicalNamed(after)) {
            return allocation(AllocationStatus.UNSUPPORTED, -1, -1, "section table",
                "canonical-width named tables", "absent, unnamed or extended-width table");
        }
        List<Range> coverage = coverage(before, cancelled);
        boolean evidence = false;
        for (ElfImage.Section x : before.sections()) {
            checkCancelled(cancelled);
            if (!allocated(x)) {
                continue;
            }
            evidence = true;
            int index = x.originalIndex;
            if (index >= after.sections().size()) {
                return allocation(AllocationStatus.DIFFERENT, index, -1, "section",
                    "allocated original index retained", "absent");
            }
            ElfImage.Section y = after.sections().get(index);
            if (!allocated(y)) {
                return allocation(AllocationStatus.DIFFERENT, index, index, "allocation",
                    "non-NULL SHF_ALLOC section", "inactive or not allocated");
            }
            if (!a.same(x, b, y)) {
                String[] difference = a.difference(x, b, y);
                return allocation(AllocationStatus.DIFFERENT, index, index, "sh_name",
                    difference[0], difference[1]);
            }
            String[] fields = {"sh_type", "sh_flags", "sh_addr", "sh_offset", "sh_size",
                "sh_link", "sh_info", "sh_addralign", "sh_entsize"};
            long[] left = fields(x);
            long[] right = fields(y);
            for (int field = 0; field < fields.length; field++) {
                if (left[field] != right[field]) {
                    return allocation(AllocationStatus.DIFFERENT, index, index, fields[field],
                        Long.toUnsignedString(left[field]), Long.toUnsignedString(right[field]));
                }
            }
            // NOBITS names a memory extent, not sh_size readable file bytes.
            // Header bytes covered by this union still have the program helper's
            // explicit section-table-field exemptions; this is not full-file proof.
            if (x.type != ElfImage.SHT_NOBITS && x.size != 0 &&
                    !covered(coverage, x.offset, end(x.offset, x.size))) {
                return allocation(AllocationStatus.UNSUPPORTED, index, index, "allocated file coverage",
                    "extent within non-NULL program payload union", "unprotected allocated file bytes");
            }
        }
        for (ElfImage.Section y : after.sections()) {
            checkCancelled(cancelled);
            int index = y.originalIndex;
            if (allocated(y) && (index >= before.sections().size() ||
                    !allocated(before.sections().get(index)))) {
                return allocation(AllocationStatus.DIFFERENT, -1, index, "allocation",
                    "no additional allocated section", "new or promoted allocation");
            }
        }
        return new AllocationObservation(evidence ? AllocationStatus.MATCHING :
            AllocationStatus.NO_ALLOCATION_EVIDENCE, Optional.empty(), evidence ?
            "indexed executable allocated fields and raw names match within program coverage" :
            "no active allocated section supplies evidence");
    }

    private static DebuglinkObservation link(ElfImage before, ElfImage after, Names a, Names b,
            byte[] basename, long crc, BooleanSupplier cancelled) throws IOException {
        if (!canonicalNamed(before) || !canonicalNamed(after)) {
            return linkIssue(DebuglinkStatus.UNSUPPORTED, -1, -1, "section table",
                "canonical-width named tables", "absent, unnamed or extended-width table");
        }
        for (ElfImage.Section section : before.sections()) {
            checkCancelled(cancelled);
            if (a.equals(section, LINK_NAME)) {
                return linkIssue(DebuglinkStatus.UNSUPPORTED, section.originalIndex, -1, "initial creation",
                    "no original .gnu_debuglink", "existing association name");
            }
        }
        ElfImage.Section selected = null;
        for (ElfImage.Section section : after.sections()) {
            checkCancelled(cancelled);
            if (b.equals(section, LINK_NAME)) {
                if (selected != null) {
                    return linkIssue(DebuglinkStatus.DIFFERENT, -1, section.originalIndex, ".gnu_debuglink count",
                        "exactly one", "multiple");
                }
                selected = section;
            }
        }
        if (selected == null) {
            return linkIssue(DebuglinkStatus.DIFFERENT, -1, -1, ".gnu_debuglink count", "one", "absent");
        }
        String[] fields = {"sh_type", "sh_flags", "sh_addr", "sh_link", "sh_info", "sh_addralign", "sh_entsize"};
        long[] values = {selected.type, selected.flags, selected.address, selected.link,
            selected.info, selected.alignment, selected.entrySize};
        long[] expected = {1, 0, 0, 0, 0, 4, 0};
        for (int field = 0; field < fields.length; field++) {
            if (values[field] != expected[field]) {
                return linkIssue(DebuglinkStatus.DIFFERENT, -1, selected.originalIndex, fields[field],
                    Long.toString(expected[field]), Long.toUnsignedString(values[field]));
            }
        }
        int crcOffset = (basename.length + 1 + 3) & ~3;
        byte[] wanted = Arrays.copyOf(basename, crcOffset + 4);
        ByteBuffer.wrap(wanted).order(after.byteOrder()).putInt(crcOffset, (int) crc);
        if (selected.size != wanted.length) {
            return linkIssue(DebuglinkStatus.DIFFERENT, -1, selected.originalIndex, "sh_size",
                Integer.toString(wanted.length), Long.toString(selected.size));
        }
        checkCancelled(cancelled);
        byte[] actual = range(after, selected.offset, selected.size, "debuglink payload");
        checkCancelled(cancelled);
        for (int index = 0; index < wanted.length; index++) {
            if ((index & 1023) == 0) {
                checkCancelled(cancelled);
            }
            if (actual[index] != wanted[index]) {
                return linkIssue(DebuglinkStatus.DIFFERENT, -1, selected.originalIndex,
                    "payload byte " + index, hex(wanted[index]), hex(actual[index]));
            }
        }
        return new DebuglinkObservation(DebuglinkStatus.MATCHING, Optional.empty(),
            "one exact GNU creation record matches literal basename and observed sidecar CRC");
    }

    private record Range(long start, long end) {
    }

    private static List<Range> coverage(ElfImage image, BooleanSupplier cancelled) throws IOException {
        List<Range> ranges = new ArrayList<>();
        for (ElfImage.Segment segment : image.segments()) {
            checkCancelled(cancelled);
            if (segment.type != 0 && segment.fileSize != 0) {
                ranges.add(new Range(segment.offset, end(segment.offset, segment.fileSize)));
            }
        }
        ranges.sort(Comparator.comparingLong(Range::start));
        List<Range> merged = new ArrayList<>();
        for (Range next : ranges) {
            checkCancelled(cancelled);
            if (merged.isEmpty() || merged.getLast().end() < next.start()) {
                merged.add(next);
            }
            else {
                Range previous = merged.removeLast();
                merged.add(new Range(previous.start(), Math.max(previous.end(), next.end())));
            }
        }
        return merged;
    }

    private static boolean covered(List<Range> ranges, long start, long end) {
        int low = 0;
        int high = ranges.size();
        while (low < high) {
            int middle = (low + high) >>> 1;
            if (ranges.get(middle).start() <= start) {
                low = middle + 1;
            }
            else {
                high = middle;
            }
        }
        return low > 0 && ranges.get(low - 1).end() >= end;
    }

    /** One raw table per input; used slices are validated/cached before comparison. */
    private static final class Names {
        private final byte[] data;
        private final Map<Integer, Integer> ends = new HashMap<>();
        private final boolean absent;

        Names(ElfImage image, BooleanSupplier cancelled) throws IOException {
            absent = image.sectionNameIndex() == 0;
            checkCancelled(cancelled);
            if (absent) {
                data = new byte[] {0};
                ends.put(0, 0);
                return;
            }
            ElfImage.Section table = image.sections().get(image.sectionNameIndex());
            if (table.size > ElfImage.MAX_NAME_TABLE_BYTES) {
                throw new IOException("raw name table exceeds 16 MiB limit");
            }
            data = range(image, table.offset, table.size, "raw section names");
            if (data.length == 0 || data[0] != 0 || data[data.length - 1] != 0) {
                throw new IOException("raw section-name framing changed");
            }
            int total = 0;
            for (ElfImage.Section section : image.sections()) {
                checkCancelled(cancelled);
                if (section.nameOffset < 0 || section.nameOffset >= data.length) {
                    throw new IOException("raw section-name offset exceeds reread table bounds");
                }
                int start = (int) section.nameOffset;
                if (ends.containsKey(start)) {
                    continue;
                }
                int stop = start;
                while (stop < data.length && data[stop] != 0) {
                    if ((stop & 1023) == 0) {
                        checkCancelled(cancelled);
                    }
                    if (stop - start == ElfImage.MAX_NAME_BYTES) {
                        throw new IOException("raw section name exceeds 65536-byte limit");
                    }
                    if (total == ElfImage.MAX_NAME_TABLE_BYTES) {
                        throw new IOException("raw used names exceed 16 MiB aggregate limit");
                    }
                    total++;
                    stop++;
                }
                if (stop == data.length) {
                    throw new IOException("unterminated raw section name");
                }
                ends.put(start, stop);
            }
            checkCancelled(cancelled);
        }

        int start(ElfImage.Section section) {
            return absent ? 0 : (int) section.nameOffset;
        }

        boolean same(ElfImage.Section a, Names other, ElfImage.Section b) {
            int x = start(a);
            int y = other.start(b);
            return Arrays.equals(data, x, ends.get(x), other.data, y, other.ends.get(y));
        }

        boolean equals(ElfImage.Section section, byte[] bytes) {
            int start = start(section);
            return Arrays.equals(data, start, ends.get(start), bytes, 0, bytes.length);
        }

        String[] difference(ElfImage.Section a, Names other, ElfImage.Section b) {
            int x = start(a);
            int y = other.start(b);
            int leftSize = ends.get(x) - x;
            int rightSize = other.ends.get(y) - y;
            int at = Arrays.mismatch(data, x, ends.get(x), other.data, y, other.ends.get(y));
            if (at < 0) {
                throw new IllegalStateException("name difference requires unequal raw names");
            }
            return new String[] {
                "name byte " + at + "=" + (at == leftSize ? "<end>" : "0x" + hex(data[x + at])) +
                    " length=" + leftSize,
                "name byte " + at + "=" + (at == rightSize ? "<end>" : "0x" + hex(other.data[y + at])) +
                    " length=" + rightSize
            };
        }
    }

    private static boolean canonicalNamed(ElfImage image) {
        ByteBuffer header = ByteBuffer.wrap(image.headerBytes()).order(image.byteOrder());
        return !image.sections().isEmpty() && image.sectionNameIndex() != 0 &&
            Short.toUnsignedInt(header.getShort(image.is64Bit() ? 58 : 46)) == (image.is64Bit() ? 64 : 40);
    }

    private static boolean allocated(ElfImage.Section section) {
        return section.originalIndex != 0 && section.type != 0 && (section.flags & 2) != 0;
    }

    private static long[] fields(ElfImage.Section x) {
        return new long[] {x.type, x.flags, x.address, x.offset, x.size, x.link, x.info, x.alignment, x.entrySize};
    }

    private static byte[] basename(byte[] value) {
        Objects.requireNonNull(value, "expectedBasename");
        if (value.length == 0 || value.length > MAX_BASENAME_BYTES) {
            throw new IllegalArgumentException("literal basename must contain 1..65536 bytes");
        }
        byte[] result = value.clone();
        for (byte b : result) {
            if (b == 0 || b == '/') {
                throw new IllegalArgumentException("literal basename contains NUL or slash");
            }
        }
        if (Arrays.equals(result, new byte[] {'.'}) || Arrays.equals(result, new byte[] {'.', '.'})) {
            throw new IllegalArgumentException("literal basename cannot be a directory component");
        }
        return result;
    }

    private static byte[] range(ElfImage image, long offset, long size, String label) throws IOException {
        try {
            return image.readSourceRange(offset, size, label);
        }
        catch (IllegalArgumentException malformed) {
            throw new IOException("invalid " + label + " for candidate content", malformed);
        }
    }

    private static ElfImage read(Path path, BooleanSupplier cancelled) throws IOException {
        checkCancelled(cancelled);
        ElfImage result;
        try {
            result = ElfImage.read(path);
        }
        catch (IllegalArgumentException malformed) {
            throw new IOException("invalid ELF for candidate content: " + path, malformed);
        }
        checkCancelled(cancelled);
        return result;
    }

    private static long end(long start, long size) throws IOException {
        try {
            return Math.addExact(start, size);
        }
        catch (ArithmeticException overflow) {
            throw new IOException("candidate allocation extent overflow", overflow);
        }
    }

    private static BasicFileAttributes attributes(Path path) throws IOException {
        BasicFileAttributes result = Files.readAttributes(path, BasicFileAttributes.class);
        if (!result.isRegularFile()) {
            throw new IOException("candidate content requires a selected regular file: " + path);
        }
        return result;
    }

    private static void unchanged(Path path, BasicFileAttributes before) throws IOException {
        BasicFileAttributes after = attributes(path);
        if (before.size() != after.size() || !before.lastModifiedTime().equals(after.lastModifiedTime()) ||
                !Objects.equals(before.fileKey(), after.fileKey())) {
            throw new IOException("selected file changed during candidate observations: " + path);
        }
    }

    private static AllocationObservation allocation(AllocationStatus status, int original, int candidate,
            String field, String expected, String observed) {
        return new AllocationObservation(status, Optional.of(new Issue(original, candidate, field, expected, observed)),
            "executable allocated-section observation: " + field);
    }

    private static DebuglinkObservation linkIssue(DebuglinkStatus status, int original, int candidate,
            String field, String expected, String observed) {
        return new DebuglinkObservation(status, Optional.of(new Issue(original, candidate, field, expected, observed)),
            "initial GNU debuglink observation: " + field);
    }

    private static void validateIssue(boolean required, Optional<Issue> issue, String diagnostic) {
        Objects.requireNonNull(issue, "issue");
        if (issue.isPresent() != required) {
            throw new IllegalArgumentException("inconsistent candidate content issue");
        }
        requireText(diagnostic, "diagnostic");
    }

    private static String hex(byte value) {
        return String.format("%02x", Byte.toUnsignedInt(value));
    }

    private static void requireText(String value, String label) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(label + " must not be blank");
        }
    }

    private static void checkCancelled(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) {
            throw new CancellationException("candidate content observation cancelled");
        }
    }
}
