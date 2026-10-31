package ghidradwarfforge.elf;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.PriorityQueue;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

import ghidradwarfforge.elf.ElfImage.Section;
import ghidradwarfforge.elf.ElfImage.Segment;

/**
 * Conservative, read-only correspondence of active allocation metadata in the
 * current Forge sidecar layout. This is not file identity, a snapshot, a proof
 * of copied bytes or valid DWARF, or attachment eligibility. Ordinary export
 * does not call this helper. Unknown target values are compared without an ISA
 * whitelist. Names are compared as used bytes, not replacement-decoded Strings.
 *
 * Both files are parsed before target/layout outcomes. Unsupported original
 * allocation transformations precede indexed differences. A match permits only
 * retained indexed sections, inert REL/RELA placeholders, and exactly derived
 * LOAD/note records and the bounded original unwind view. It does not validate
 * the original's complete runtime map.
 *
 * ElfImage's metadata bounds and signed offset/address model apply. Additionally
 * at most 65536 nonempty note views are considered, with at most 262144 merged
 * coverage intervals/expected records. Note processing is indexed, not quadratic.
 * No whole file or code payload is read. Sectionless unwind discovery reads
 * bounded header/search-table/CIE/FDE framing metadata, not call-frame programs;
 * used name tables remain bounded at 16 MiB each. These limits do not promise
 * that all maximum metadata combinations fit a 64 MiB heap. ElfImage owns/closes
 * its channels, including name reads.
 * Cancellation is checked around parser calls and during every bounded walk;
 * it cannot interrupt a blocked filesystem call or every internal parser read.
 */
public final class MatchedElfAllocations {
    static final int MAX_NOTE_VIEWS = 65536;
    private static final long ALLOC = 2;
    private static final long NOTE = 7;
    private static final long NOBITS = 8;

    public enum Status {
        MATCHING_ALLOCATED_METADATA, DIFFERENT_METADATA, UNSUPPORTED_CASE,
        NO_ALLOCATION_EVIDENCE
    }

    public enum Origin {
        HEADER, ORIGINAL_SECTION, ORIGINAL_SEGMENT, CANDIDATE_SECTION
    }

    /** An index of -1 means there is no corresponding index, never section zero. */
    public record Issue(Origin origin, int originalIndex, int candidateIndex,
            String field, String reason, String expected, String observed) {
        public Issue {
            Objects.requireNonNull(origin, "origin");
            if (originalIndex < -1 || candidateIndex < -1) {
                throw new IllegalArgumentException("invalid issue index");
            }
            requireText(field, "field");
            requireText(reason, "reason");
            requireText(expected, "expected");
            requireText(observed, "observed");
        }
    }

    public record Result(Status status, Optional<Issue> issue, String diagnostic) {
        public Result {
            Objects.requireNonNull(status, "status");
            Objects.requireNonNull(issue, "issue");
            requireText(diagnostic, "diagnostic");
            boolean needsIssue = status == Status.DIFFERENT_METADATA || status == Status.UNSUPPORTED_CASE;
            if (needsIssue != issue.isPresent()) {
                throw new IllegalArgumentException("inconsistent allocation observation");
            }
        }
    }

    private record NoteView(long start, long end, long bias, boolean segment,
            boolean allocated, int index) {
    }

    private MatchedElfAllocations() {
    }

    public static Result compare(Path original, Path candidate) throws IOException {
        return compare(original, candidate, () -> false);
    }

    public static Result compare(Path original, Path candidate, BooleanSupplier cancelled)
            throws IOException {
        Objects.requireNonNull(original, "original");
        Objects.requireNonNull(candidate, "candidate");
        Objects.requireNonNull(cancelled, "cancelled");
        checkCancelled(cancelled);
        BasicFileAttributes originalState = attributes(original);
        BasicFileAttributes candidateState = attributes(candidate);
        ElfImage before = read(original, "original", cancelled);
        ElfImage after = read(candidate, "candidate", cancelled);
        if (before.fileSize() != originalState.size() || after.fileSize() != candidateState.size()) {
            throw new IOException("ELF size changed during allocation observation");
        }
        Result result = new Comparison(before, after, cancelled).compare();
        requireUnchanged(original, originalState);
        requireUnchanged(candidate, candidateState);
        checkCancelled(cancelled);
        return result;
    }

    private static ElfImage read(Path path, String label, BooleanSupplier cancelled) throws IOException {
        checkCancelled(cancelled);
        ElfImage result;
        try {
            result = ElfImage.read(path);
        }
        catch (IllegalArgumentException malformed) {
            throw new IOException("invalid " + label + " ELF metadata for allocation observation", malformed);
        }
        checkCancelled(cancelled);
        return result;
    }

    private static final class Comparison {
        private final ElfImage before;
        private final ElfImage after;
        private final BooleanSupplier cancelled;
        private final BitSet accounted = new BitSet();
        private Names originalNames;
        private Names candidateNames;

        Comparison(ElfImage before, ElfImage after, BooleanSupplier cancelled) {
            this.before = before;
            this.after = after;
            this.cancelled = cancelled;
        }

        Result compare() throws IOException {
            Result result = targetAndLayout();
            if (result != null) {
                return result;
            }
            originalNames = new Names(before, cancelled);
            candidateNames = new Names(after, cancelled);
            for (Section section : before.sections()) {
                checkCancelled(cancelled);
                if (!active(section)) {
                    continue;
                }
                int index = section.originalIndex;
                if (!originalNames.roundTrips(section)) {
                    return unsupported(Origin.ORIGINAL_SECTION, index, index, "sh_name",
                        "used allocated name does not round-trip through the current writer encoding",
                        "unchanged used name bytes", originalNames.display(section));
                }
                if (index == before.sectionNameIndex()) {
                    return unsupported(Origin.ORIGINAL_SECTION, index, index, "sh_name",
                        "allocated original name table is renamed by the current writer",
                        "retained allocated name", ".shstrtab.old");
                }
                // Relocation names normally survive, but a .debug_* name can
                // subsequently receive a replacement payload and lose ALLOC.
                boolean relocation = section.type == 4 || section.type == 9;
                if (inheritedDebug(section.name) && (!relocation || section.name.startsWith(".debug_"))) {
                    return unsupported(Origin.ORIGINAL_SECTION, index, index, "sh_flags/sh_name",
                        "allocated debug metadata may be replaced or retired",
                        "retained allocated metadata", "writer debug transformation is unsupported here");
                }
            }
            List<NoteView> views = noteViews();
            result = ambiguousNotes(views);
            if (result != null) {
                return result;
            }
            int appendedIndex;
            if (before.sections().isEmpty()) {
                appendedIndex = 1;
                for (int index = 0; index < before.segments().size(); index++) {
                    checkCancelled(cancelled);
                    Segment segment = before.segments().get(index);
                    if (segment.type != 1 || segment.memorySize == 0) {
                        continue;
                    }
                    if (!addressRange(segment.virtualAddress, segment.memorySize, before.is64Bit())) {
                        return unsupported(Origin.ORIGINAL_SEGMENT, index, appendedIndex, "p_vaddr/p_memsz",
                            "load extent exceeds the current writer address model",
                            "representable exclusive end", "address=" + number(segment.virtualAddress) +
                                " size=" + number(segment.memorySize));
                    }
                    Section expected = new Section();
                    expected.name = ".forge.load." + index;
                    expected.type = NOBITS;
                    expected.flags = ALLOC | ((segment.flags & 2) != 0 ? 1 : 0) |
                        ((segment.flags & 1) != 0 ? 4 : 0);
                    expected.address = segment.virtualAddress;
                    expected.offset = segment.offset;
                    expected.size = segment.memorySize;
                    expected.alignment = 1;
                    result = section(Origin.ORIGINAL_SEGMENT, index, appendedIndex++, expected, null);
                    if (result != null) {
                        return result;
                    }
                }
                Section unwind = SectionlessUnwind.find(before, cancelled, ignored -> { });
                if (unwind != null) {
                    int headerIndex = -1;
                    for (int index = 0; index < before.segments().size(); index++) {
                        checkCancelled(cancelled);
                        if (before.segments().get(index).type == 0x6474e550L) {
                            headerIndex = index;
                        }
                    }
                    result = section(Origin.ORIGINAL_SEGMENT, headerIndex, appendedIndex++, unwind, null);
                    if (result != null) {
                        return result;
                    }
                }
            }
            else {
                appendedIndex = before.sections().size();
                for (Section original : before.sections()) {
                    checkCancelled(cancelled);
                    if (!active(original)) {
                        continue;
                    }
                    Section expected = original.copy();
                    if (original.type == 4 || original.type == 9) {
                        expected.type = NOBITS;
                        expected.flags = ALLOC;
                        expected.link = 0;
                        expected.info = 0;
                        expected.entrySize = 0;
                    }
                    result = section(Origin.ORIGINAL_SECTION, original.originalIndex,
                        original.originalIndex, expected, original);
                    if (result != null) {
                        return result;
                    }
                }
            }
            result = reconstructedNotes(appendedIndex);
            if (result != null) {
                return result;
            }
            for (Section section : after.sections()) {
                checkCancelled(cancelled);
                if (active(section) && !accounted.get(section.originalIndex)) {
                    return difference(Origin.CANDIDATE_SECTION, -1, section.originalIndex, "sh_flags",
                        "unexpected active allocated section", "no additional allocation",
                        candidateNames.display(section));
                }
            }
            boolean empty = accounted.isEmpty();
            return new Result(empty ? Status.NO_ALLOCATION_EVIDENCE : Status.MATCHING_ALLOCATED_METADATA,
                Optional.empty(), empty ? "no active allocated metadata supplies correspondence evidence"
                    : "indexed allocation metadata corresponds under the conservative current-writer rules");
        }

        private Result targetAndLayout() {
            byte[] a = before.headerBytes();
            byte[] b = after.headerBytes();
            String[] byteNames = { "EI_CLASS", "EI_DATA", "EI_OSABI", "EI_ABIVERSION" };
            int[] offsets = { 4, 5, 7, 8 };
            for (int index = 0; index < offsets.length; index++) {
                if (a[offsets[index]] != b[offsets[index]]) {
                    return header(byteNames[index], Byte.toUnsignedInt(a[offsets[index]]),
                        Byte.toUnsignedInt(b[offsets[index]]));
                }
            }
            if (before.type() != after.type()) {
                return header("e_type", before.type(), after.type());
            }
            if (before.machine() != after.machine()) {
                return header("e_machine", before.machine(), after.machine());
            }
            if (before.flags() != after.flags()) {
                return header("e_flags", before.flags(), after.flags());
            }
            ByteBuffer x = ByteBuffer.wrap(a).order(before.byteOrder());
            ByteBuffer y = ByteBuffer.wrap(b).order(after.byteOrder());
            boolean wide = before.is64Bit();
            long entryA = wide ? x.getLong(24) : Integer.toUnsignedLong(x.getInt(24));
            long entryB = wide ? y.getLong(24) : Integer.toUnsignedLong(y.getInt(24));
            if (entryA != entryB) {
                return header("e_entry", entryA, entryB);
            }
            long phoff = wide ? y.getLong(32) : Integer.toUnsignedLong(y.getInt(28));
            int phsize = Short.toUnsignedInt(y.getShort(wide ? 54 : 42));
            int phnum = Short.toUnsignedInt(y.getShort(wide ? 56 : 44));
            if (phoff != 0 || phsize != 0 || phnum != 0) {
                return difference(Origin.HEADER, -1, -1, "program table", "candidate is not a matched sidecar",
                    "zero offset, entry size and count", number(phoff) + "/" + phsize + "/" + phnum);
            }
            long shoff = wide ? y.getLong(40) : Integer.toUnsignedLong(y.getInt(32));
            int shsize = Short.toUnsignedInt(y.getShort(wide ? 58 : 46));
            if (shoff < before.fileSize() || after.sections().isEmpty() ||
                    shsize != (wide ? 64 : 40) || after.sectionNameIndex() == 0) {
                return difference(Origin.HEADER, -1, -1, "section table", "candidate layout is outside current-writer envelope",
                    "appended nonempty canonical table with names", "offset=" + number(shoff) +
                        " entry-size=" + shsize + " name-index=" + after.sectionNameIndex());
            }
            return null;
        }

        private Result header(String field, long expected, long observed) {
            return difference(Origin.HEADER, -1, -1, field, "target metadata differs",
                number(expected), number(observed));
        }

        private Result section(Origin origin, int originalIndex, int candidateIndex,
                Section expected, Section originalName) {
            checkCancelled(cancelled);
            if (candidateIndex >= ElfImage.MAX_HEADER_COUNT) {
                return unsupported(origin, originalIndex, candidateIndex, "section count",
                    "derived allocation count exceeds the supported metadata bound",
                    "at most " + ElfImage.MAX_HEADER_COUNT, Integer.toString(candidateIndex + 1));
            }
            if (candidateIndex >= after.sections().size()) {
                return difference(origin, originalIndex, candidateIndex, "section index",
                    "expected allocated section is missing", "present", "absent");
            }
            Section actual = after.sections().get(candidateIndex);
            boolean sameName = originalName == null
                ? candidateNames.equalsBytes(actual, expected.name.getBytes(StandardCharsets.UTF_8))
                : originalNames.equalsName(originalName, candidateNames, actual);
            if (!sameName) {
                return difference(origin, originalIndex, candidateIndex, "sh_name", "used name bytes differ",
                    originalName == null ? expected.name : originalNames.display(originalName),
                    candidateNames.display(actual));
            }
            long[] wanted = { expected.type, expected.flags, expected.address, expected.offset,
                expected.size, expected.link, expected.info, expected.alignment, expected.entrySize };
            long[] found = { actual.type, actual.flags, actual.address, actual.offset,
                actual.size, actual.link, actual.info, actual.alignment, actual.entrySize };
            String[] fields = { "sh_type", "sh_flags", "sh_addr", "sh_offset", "sh_size",
                "sh_link", "sh_info", "sh_addralign", "sh_entsize" };
            for (int index = 0; index < fields.length; index++) {
                if (wanted[index] != found[index]) {
                    return difference(origin, originalIndex, candidateIndex, fields[index],
                        "indexed allocation metadata differs", number(wanted[index]), number(found[index]));
                }
            }
            accounted.set(candidateIndex);
            return null;
        }

        private List<NoteView> noteViews() throws IOException {
            List<NoteView> result = new ArrayList<>();
            for (Section section : before.sections()) {
                checkCancelled(cancelled);
                if (section.type == NOTE && section.size != 0) {
                    addView(result, new NoteView(section.offset, end(section.offset, section.size),
                        section.address - section.offset, false, active(section), section.originalIndex));
                }
            }
            for (int index = 0; index < before.segments().size(); index++) {
                checkCancelled(cancelled);
                Segment segment = before.segments().get(index);
                if (segment.type == 4 && segment.fileSize != 0) {
                    addView(result, new NoteView(segment.offset, end(segment.offset, segment.fileSize),
                        segment.virtualAddress - segment.offset, true, true, index));
                }
            }
            result.sort(Comparator.comparingLong(NoteView::start).thenComparingLong(NoteView::end)
                .thenComparing(NoteView::segment).thenComparingInt(NoteView::index));
            checkCancelled(cancelled);
            return result;
        }

        private void addView(List<NoteView> views, NoteView view) throws IOException {
            if (views.size() == MAX_NOTE_VIEWS) {
                throw new IOException("note view count exceeds allocation observation limit " + MAX_NOTE_VIEWS);
            }
            views.add(view);
        }

        private Result ambiguousNotes(List<NoteView> views) {
            PriorityQueue<NoteView> active = new PriorityQueue<>(Comparator.comparingLong(NoteView::end));
            TreeMap<Long, Integer> segments = new TreeMap<>();
            TreeMap<Long, Integer> sections = new TreeMap<>();
            int nonallocated = 0;
            for (NoteView view : views) {
                checkCancelled(cancelled);
                while (!active.isEmpty() && active.peek().end() <= view.start()) {
                    NoteView old = active.remove();
                    decrement(old.segment() ? segments : sections, old.bias());
                    if (!old.segment() && !old.allocated()) {
                        nonallocated--;
                    }
                }
                boolean ambiguous = view.segment()
                    ? nonallocated != 0 || differentBias(segments, view.bias()) || differentBias(sections, view.bias())
                    : !segments.isEmpty() && (!view.allocated() || differentBias(segments, view.bias()));
                if (ambiguous) {
                    return unsupported(view.segment() ? Origin.ORIGINAL_SEGMENT : Origin.ORIGINAL_SECTION,
                        view.index(), -1, "note address mapping", "overlapping note views lack one allocated mapping",
                        "equal allocated VA/file-offset mappings", "conflicting or nonallocated physical coverage");
                }
                (view.segment() ? segments : sections).merge(view.bias(), 1, Integer::sum);
                if (!view.segment() && !view.allocated()) {
                    nonallocated++;
                }
                active.add(view);
            }
            return null;
        }

        private Result reconstructedNotes(int firstIndex) throws IOException {
            TreeMap<Long, Long> covered = new TreeMap<>();
            for (Section section : before.sections()) {
                checkCancelled(cancelled);
                if (section.type == NOTE && section.size != 0) {
                    cover(covered, section.offset, end(section.offset, section.size));
                }
            }
            int count = 0;
            for (int index = 0; index < before.segments().size(); index++) {
                checkCancelled(cancelled);
                Segment segment = before.segments().get(index);
                if (segment.type != 4 || segment.fileSize == 0) {
                    continue;
                }
                long limit = end(segment.offset, segment.fileSize);
                long position = segment.offset;
                while (position < limit) {
                    checkCancelled(cancelled);
                    Map.Entry<Long, Long> previous = covered.floorEntry(position);
                    if (previous != null && previous.getValue() > position) {
                        position = Math.min(limit, previous.getValue());
                        continue;
                    }
                    Map.Entry<Long, Long> next = covered.ceilingEntry(position);
                    long stop = next == null ? limit : Math.min(limit, next.getKey());
                    long alignment = Math.max(1, segment.alignment);
                    if (stop - position < 12 || (position - segment.offset) % alignment != 0) {
                        return unsupported(Origin.ORIGINAL_SEGMENT, index, firstIndex + count,
                            "note gap", "uncovered note range is outside the current writer framing policy",
                            "at least 12 bytes with aligned displacement", number(position) + ".." + number(stop));
                    }
                    if (segment.virtualAddress > Long.MAX_VALUE - (position - segment.offset)) {
                        return unsupported(Origin.ORIGINAL_SEGMENT, index, firstIndex + count,
                            "p_vaddr", "reconstructed note address overflows signed address model",
                            "representable note address", "overflow");
                    }
                    Section expected = new Section();
                    expected.name = ".note.forge." + count;
                    expected.type = NOTE;
                    expected.flags = ALLOC;
                    expected.address = segment.virtualAddress + (position - segment.offset);
                    expected.offset = position;
                    expected.size = stop - position;
                    expected.alignment = alignment;
                    if (!before.is64Bit() && expected.address > 0xffff_ffffL) {
                        return unsupported(Origin.ORIGINAL_SEGMENT, index, firstIndex + count,
                            "sh_addr", "reconstructed note address exceeds ELF32 field",
                            "unsigned 32-bit address", number(expected.address));
                    }
                    Result result = section(Origin.ORIGINAL_SEGMENT, index, firstIndex + count,
                        expected, null);
                    if (result != null) {
                        return result;
                    }
                    count++;
                    cover(covered, position, stop);
                    position = stop;
                }
            }
            return null;
        }

        private void cover(TreeMap<Long, Long> ranges, long start, long end) throws IOException {
            Map.Entry<Long, Long> previous = ranges.floorEntry(start);
            if (previous != null && previous.getValue() >= start) {
                start = previous.getKey();
                end = Math.max(end, previous.getValue());
                ranges.remove(previous.getKey());
            }
            Map.Entry<Long, Long> next = ranges.ceilingEntry(start);
            while (next != null && next.getKey() <= end) {
                checkCancelled(cancelled);
                end = Math.max(end, next.getValue());
                ranges.remove(next.getKey());
                next = ranges.ceilingEntry(start);
            }
            ranges.put(start, end);
            if (ranges.size() > ElfImage.MAX_HEADER_COUNT) {
                throw new IOException("note coverage exceeds allocation observation limit");
            }
        }
    }

    /** Raw used slices share one bounded table; duplicate offsets are scanned once. */
    private static final class Names {
        private final byte[] bytes;
        private final Map<Integer, Integer> ends = new HashMap<>();
        private final Set<Integer> checked = new HashSet<>();
        private final Set<Integer> roundTrips = new HashSet<>();
        private final BooleanSupplier cancelled;
        private int scannedBytes;

        Names(ElfImage image, BooleanSupplier cancelled) throws IOException {
            this.cancelled = cancelled;
            checkCancelled(cancelled);
            bytes = image.sectionNameIndex() == 0 ? new byte[] { 0 }
                : image.sectionData(image.sections().get(image.sectionNameIndex()));
            if (bytes.length == 0 || bytes[0] != 0 || bytes[bytes.length - 1] != 0) {
                throw new IOException("section-name framing changed during allocation observation");
            }
            // The table was read again after metadata parsing. Enforce its own
            // used-slice bounds even if a change escaped attribute checks.
            for (Section section : image.sections()) {
                checkCancelled(cancelled);
                validate(section);
            }
            checkCancelled(cancelled);
        }

        private int start(Section section) {
            // SHN_UNDEF has no used name, irrespective of uninterpreted sh_name.
            return bytes.length == 1 ? 0 : Math.toIntExact(section.nameOffset);
        }

        private int end(Section section) {
            return ends.get(start(section));
        }

        private void validate(Section section) throws IOException {
            long rawOffset = bytes.length == 1 ? 0 : section.nameOffset;
            if (rawOffset < 0 || rawOffset >= bytes.length) {
                throw new IOException("raw section-name offset exceeds reread table bounds");
            }
            int offset = (int) rawOffset;
            if (ends.containsKey(offset)) {
                return;
            }
            int stop = offset;
            while (stop < bytes.length && bytes[stop] != 0) {
                if ((stop & 1023) == 0) {
                    checkCancelled(cancelled);
                }
                if (stop - offset == ElfImage.MAX_NAME_BYTES) {
                    throw new IOException("raw section name exceeds reread limit " + ElfImage.MAX_NAME_BYTES);
                }
                if (scannedBytes == ElfImage.MAX_NAME_TABLE_BYTES) {
                    throw new IOException("raw section names exceed aggregate reread limit " + ElfImage.MAX_NAME_TABLE_BYTES);
                }
                stop++;
                scannedBytes++;
            }
            if (stop == bytes.length) {
                throw new IOException("unterminated raw section name after table reread");
            }
            ends.put(offset, stop);
        }

        boolean roundTrips(Section section) {
            int start = start(section);
            if (checked.add(start) && equalsBytes(section, section.name.getBytes(StandardCharsets.UTF_8))) {
                roundTrips.add(start);
            }
            return roundTrips.contains(start);
        }

        boolean equalsBytes(Section section, byte[] expected) {
            return Arrays.equals(bytes, start(section), end(section), expected, 0, expected.length);
        }

        boolean equalsName(Section first, Names other, Section second) {
            return Arrays.equals(bytes, start(first), end(first), other.bytes, other.start(second), other.end(second));
        }

        String display(Section section) {
            int start = start(section);
            int end = end(section);
            StringBuilder result = new StringBuilder("bytes[").append(end - start).append("]=");
            for (int index = start; index < Math.min(end, start + 32); index++) {
                result.append(Character.forDigit((bytes[index] >>> 4) & 15, 16));
                result.append(Character.forDigit(bytes[index] & 15, 16));
            }
            return result.append(end - start > 32 ? "..." : "").toString();
        }
    }

    private static boolean differentBias(TreeMap<Long, Integer> values, long bias) {
        return !values.isEmpty() && (values.firstKey() != bias || values.lastKey() != bias);
    }

    private static void decrement(TreeMap<Long, Integer> values, long key) {
        int count = values.get(key);
        if (count == 1) {
            values.remove(key);
        }
        else {
            values.put(key, count - 1);
        }
    }

    private static boolean active(Section section) {
        return section.originalIndex != 0 && section.type != 0 && (section.flags & ALLOC) != 0;
    }

    private static boolean inheritedDebug(String name) {
        return name.startsWith(".debug_") || name.startsWith(".zdebug_") ||
            name.startsWith(".rel.debug_") || name.startsWith(".rela.debug_") ||
            name.equals(".gdb_index") || name.equals(".gnu_debuglink") ||
            name.equals(".gnu_debugaltlink") || name.equals(".gnu_debugdata");
    }

    private static boolean addressRange(long start, long size, boolean wide) {
        return size <= Long.MAX_VALUE - start && (wide || start + size <= 0x1_0000_0000L);
    }

    private static long end(long start, long size) throws IOException {
        try {
            return Math.addExact(start, size);
        }
        catch (ArithmeticException overflow) {
            throw new IOException("allocation observation offset overflow", overflow);
        }
    }

    private static BasicFileAttributes attributes(Path path) throws IOException {
        BasicFileAttributes result = Files.readAttributes(path, BasicFileAttributes.class);
        if (!result.isRegularFile()) {
            throw new IOException("allocation observation requires a regular ELF file: " + path);
        }
        return result;
    }

    private static void requireUnchanged(Path path, BasicFileAttributes before) throws IOException {
        BasicFileAttributes after = attributes(path);
        if (before.size() != after.size() || !before.lastModifiedTime().equals(after.lastModifiedTime()) ||
                !Objects.equals(before.fileKey(), after.fileKey())) {
            throw new IOException("ELF changed during allocation observation: " + path);
        }
    }

    private static Result difference(Origin origin, int original, int candidate, String field,
            String reason, String expected, String observed) {
        return issue(Status.DIFFERENT_METADATA, origin, original, candidate, field, reason, expected, observed);
    }

    private static Result unsupported(Origin origin, int original, int candidate, String field,
            String reason, String expected, String observed) {
        return issue(Status.UNSUPPORTED_CASE, origin, original, candidate, field, reason, expected, observed);
    }

    private static Result issue(Status status, Origin origin, int original, int candidate,
            String field, String reason, String expected, String observed) {
        return new Result(status, Optional.of(new Issue(origin, original, candidate, field, reason, expected, observed)),
            reason + " (" + field + ")");
    }

    private static String number(long value) {
        return "0x" + Long.toUnsignedString(value, 16);
    }

    private static void requireText(String text, String label) {
        if (text == null || text.isBlank()) {
            throw new IllegalArgumentException(label + " must be nonblank");
        }
    }

    private static void checkCancelled(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) {
            throw new CancellationException("ELF allocation observation cancelled");
        }
    }
}
