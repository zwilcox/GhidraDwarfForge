package ghidradwarfforge.elf;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

import ghidradwarfforge.elf.ElfImage.Section;

/** Conservative ARM ELF cues for homogeneous recovered functions, not section mapping symbols. */
public final class Arm32ModeSymbols {
    private static final int MAX_CUES = 65536;
    private static final int MAX_DYNAMIC_SYMBOLS = 262144;
    private static final long UINT32_END = 0x1_0000_0000L;

    private static final class UnsupportedSymbols extends RuntimeException {
        UnsupportedSymbols(String message) {
            super(message);
        }
    }

    private record Extent(int index, long address, long size, long offset,
            long fileSize, boolean ordinary) {
        boolean contains(long start, long length) {
            return start >= address && start - address <= size &&
                length <= size - (start - address);
        }

        boolean intersects(long start, long length) {
            return start < address ? address - start < length : start - address < size;
        }
    }

    private Arm32ModeSymbols() {
    }

    /**
     * Extended executable layouts share the audited alias byte/owner binding and
     * original mode inventory. These synthetic names are ELF mode hints only;
     * they are never exported as analyst aliases or DWARF declarations.
     */
    public static List<ElfLocalFunctionSymbol> planRecovered(ElfImage image,
            List<ElfFunctionModeCue> cues,
            List<ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol> functions,
            BooleanSupplier cancelled, Consumer<String> diagnostic) throws IOException {
        checkCancelled(cancelled);
        if (cues.size() > MAX_CUES) {
            diagnostic.accept("Omitted ARM32 mode symbols: cue count exceeds " + MAX_CUES);
            return List.of();
        }
        if (cues.stream().noneMatch(cue -> (cue.symbolValue() & 1) != 0)) {
            return List.of();
        }
        var bindings = new ArrayList<ElfFunctionAlias>();
        for (var cue : cues) {
            checkCancelled(cancelled);
            String name = "__forge_arm_mode_" + String.format(java.util.Locale.ROOT, "%08x", cue.address());
            if (name.equals(cue.displayName())) {
                diagnostic.accept("Omitted ARM32 mode cue " + cue.displayName() + ": synthetic name conflicts with owner");
                continue;
            }
            bindings.add(new ElfFunctionAlias(name, cue.displayName(), cue.address(), cue.size(), cue.codeSha256()));
        }
        var planned = Arm32FunctionAliasSymbols.plan(image, bindings, functions, List.of(), cues,
            cancelled, message -> diagnostic.accept(message.replace("function aliases", "ARM32 mode symbols")
                .replace("function alias", "ARM32 mode cue")));
        if (planned.stream().noneMatch(symbol -> (symbol.value() & 1) != 0)) {
            diagnostic.accept("Omitted ARM32 mode symbols: no eligible Thumb cue remains");
            return List.of();
        }
        return planned;
    }

    public static List<ElfLocalFunctionSymbol> plan(ElfImage image,
            List<ElfFunctionModeCue> cues, BooleanSupplier cancelled,
            Consumer<String> diagnostic) throws IOException {
        Objects.requireNonNull(image, "image");
        Objects.requireNonNull(cues, "cues");
        Objects.requireNonNull(cancelled, "cancelled");
        Objects.requireNonNull(diagnostic, "diagnostic");
        checkCancelled(cancelled);
        if (image.machine() != 40 || image.is64Bit() ||
                image.byteOrder() != ByteOrder.LITTLE_ENDIAN) {
            throw new IllegalArgumentException("ARM mode-symbol planner requires audited ELF32 LE ARM");
        }
        if (cues.size() > MAX_CUES) {
            diagnostic.accept("Omitted ARM32 mode symbols: cue count exceeds " + MAX_CUES);
            return List.of();
        }
        if (cues.stream().noneMatch(cue -> (cue.symbolValue() & 1) != 0)) {
            return List.of();
        }
        if (image.type() != 2) {
            diagnostic.accept("Omitted ARM32 mode symbols: only ET_EXEC mode cues are audited");
            return List.of();
        }
        if (image.sections().isEmpty()) {
            diagnostic.accept("Omitted ARM32 mode symbols: sectionless mode-cue binding is not audited");
            return List.of();
        }
        for (Section section : image.sections()) {
            checkCancelled(cancelled);
            if (section.type == 2) {
                diagnostic.accept("Omitted ARM32 mode symbols: existing SHT_SYMTAB is preserved; " +
                    "its instruction-mode coverage is not verified");
                return List.of();
            }
            if (section.name.equals(".symtab") || section.name.equals(".strtab") ||
                    section.name.equals(".symtab_shndx")) {
                diagnostic.accept("Omitted ARM32 mode symbols: reserved section name collision " +
                    section.name);
                return List.of();
            }
        }
        List<Extent> extents = extents(image, cancelled);
        if ((long) extents.size() * cues.size() > 16L * 1024 * 1024) {
            diagnostic.accept("Omitted ARM32 mode symbols: allocation comparison budget exceeded");
            return List.of();
        }
        Map<Integer, TreeMap<Long, Long>> dynamic;
        try {
            dynamic = dynamicRanges(image, extents, cancelled);
        }
        catch (UnsupportedSymbols unsupported) {
            diagnostic.accept("Omitted ARM32 mode symbols: " + unsupported.getMessage());
            return List.of();
        }
        List<ElfFunctionModeCue> ordered = new ArrayList<>(cues);
        ordered.sort(Comparator.comparingLong(ElfFunctionModeCue::address)
            .thenComparing(ElfFunctionModeCue::displayName));
        boolean[] overlaps = new boolean[ordered.size()];
        // A cluster may have a long interval containing many shorter intervals.
        int clusterStart = 0;
        long clusterEnd = -1;
        for (int index = 0; index < ordered.size(); index++) {
            checkCancelled(cancelled);
            ElfFunctionModeCue cue = ordered.get(index);
            if (cue.address() < clusterEnd) {
                overlaps[clusterStart] = true;
                overlaps[index] = true;
            }
            else {
                clusterStart = index;
            }
            clusterEnd = Math.max(clusterEnd, cue.address() + cue.size());
        }
        List<ElfLocalFunctionSymbol> result = new ArrayList<>();
        boolean hasThumb = false;
        try (FileChannel input = FileChannel.open(image.sourcePath(), StandardOpenOption.READ)) {
            image.requireUnchanged(input);
            ByteBuffer bytes = ByteBuffer.allocate(65536);
            for (int index = 0; index < ordered.size(); index++) {
                checkCancelled(cancelled);
                ElfFunctionModeCue cue = ordered.get(index);
                String reason = null;
                boolean thumb = cue.symbolValue() == (cue.address() | 1);
                if (cue.address() >= UINT32_END || cue.size() >= UINT32_END ||
                        cue.size() > UINT32_END - cue.address() ||
                        (cue.address() & 1) != 0 ||
                        (cue.symbolValue() != cue.address() && !thumb) ||
                        (!thumb && ((cue.address() | cue.size()) & 3) != 0) ||
                        (thumb && (cue.size() & 1) != 0)) {
                    reason = "invalid ARM/Thumb encoded value, extent or alignment";
                }
                else if (overlaps[index]) {
                    reason = "overlapping recovered function intervals";
                }
                Extent selected = null;
                int matches = 0;
                if (reason == null) {
                    for (Extent extent : extents) {
                        checkCancelled(cancelled);
                        if (extent.intersects(cue.address(), cue.size())) {
                            selected = extent;
                            matches++;
                        }
                    }
                    if (matches != 1 || !selected.contains(cue.address(), cue.size())) {
                        reason = "function has no unique executable allocation";
                    }
                    else if (!selected.ordinary() ||
                            cue.address() - selected.address() > selected.fileSize() ||
                            cue.size() > selected.fileSize() - (cue.address() - selected.address())) {
                        reason = "function is not entirely backed by original code bytes";
                    }
                }
                if (reason == null && overlaps(dynamic.get(selected.index()),
                        cue.address(), cue.address() + cue.size())) {
                    reason = "existing dynamic code symbol may take precedence";
                }
                if (reason == null) {
                    long offset = Math.addExact(selected.offset(),
                        cue.address() - selected.address());
                    if (!hash(input, offset, cue.size(), bytes, cancelled).equals(cue.codeSha256())) {
                        reason = "decoded instruction bytes differ from selected original ELF";
                    }
                }
                if (reason != null) {
                    diagnostic.accept("Omitted ARM32 mode cue " + cue.displayName() + " at 0x" +
                        Long.toHexString(cue.address()) + ": " + reason);
                    continue;
                }
                result.add(new ElfLocalFunctionSymbol(
                    "__forge_arm_mode_" + String.format(java.util.Locale.ROOT, "%08x", cue.address()),
                    cue.symbolValue(), cue.size(), selected.index()));
                hasThumb |= thumb;
            }
            checkCancelled(cancelled);
            image.requireUnchanged(input);
        }
        if (!hasThumb) {
            diagnostic.accept("Omitted ARM32 mode symbols: no eligible Thumb cue remains");
            return List.of();
        }
        return List.copyOf(result);
    }

    private static List<Extent> extents(ElfImage image, BooleanSupplier cancelled) {
        List<Extent> result = new ArrayList<>();
        for (Section section : image.sections()) {
            checkCancelled(cancelled);
            if ((section.flags & 6) == 6 && section.size > 0) {
                result.add(new Extent(section.originalIndex, section.address, section.size,
                    section.offset, section.size, section.type == 1 &&
                        section.address < UINT32_END && section.size <= UINT32_END - section.address));
            }
        }
        return result;
    }

    private static Map<Integer, TreeMap<Long, Long>> dynamicRanges(ElfImage image,
            List<Extent> extents, BooleanSupplier cancelled) throws IOException {
        Map<Integer, Extent> code = new HashMap<>();
        for (Extent extent : extents) {
            code.put(extent.index(), extent);
        }
        Map<Integer, TreeMap<Long, Long>> result = new HashMap<>();
        Map<Integer, Section> indexTables = new HashMap<>();
        for (Section section : image.sections()) {
            checkCancelled(cancelled);
            if (section.type == 18 && section.link > 0 && section.link < image.sections().size() &&
                    image.sections().get((int) section.link).type == 11 &&
                    indexTables.putIfAbsent((int) section.link, section) != null) {
                throw new UnsupportedSymbols("duplicate dynamic extended-index tables");
            }
        }
        int total = 0;
        for (Section table : image.sections()) {
            checkCancelled(cancelled);
            if (table.type != 11) {
                continue;
            }
            if (table.entrySize != 16 || table.size % 16 != 0 || table.size == 0 ||
                    table.size / 16 > MAX_DYNAMIC_SYMBOLS - total || table.link <= 0 ||
                    table.link >= image.sections().size() ||
                    image.sections().get((int) table.link).type != 3) {
                throw new UnsupportedSymbols("unsupported dynamic-symbol table framing");
            }
            int count = Math.toIntExact(table.size / 16);
            total += count;
            ByteBuffer rows = ByteBuffer.wrap(image.sectionData(table)).order(image.byteOrder());
            ByteBuffer extended = null;
            Section other = indexTables.get(table.originalIndex);
            if (other != null) {
                if (other.entrySize != 4 || other.size != (long) count * 4) {
                    throw new UnsupportedSymbols("unsupported dynamic extended-index table");
                }
                extended = ByteBuffer.wrap(image.sectionData(other)).order(image.byteOrder());
            }
            for (int index = 0; index < 16; index++) {
                if (rows.get(index) != 0) {
                    throw new UnsupportedSymbols("dynamic-symbol row zero is not null");
                }
            }
            for (int index = 0; index < count; index++) {
                checkCancelled(cancelled);
                int at = index * 16;
                long value = Integer.toUnsignedLong(rows.getInt(at + 4));
                long size = Integer.toUnsignedLong(rows.getInt(at + 8));
                int type = rows.get(at + 12) & 15;
                int encoded = Short.toUnsignedInt(rows.getShort(at + 14));
                long sectionIndex = encoded;
                if (encoded == 0xffff) {
                    if (extended == null) {
                        throw new UnsupportedSymbols("missing dynamic extended section index");
                    }
                    sectionIndex = Integer.toUnsignedLong(extended.getInt(index * 4));
                    if (sectionIndex < 0xff00 || sectionIndex >= image.sections().size()) {
                        throw new UnsupportedSymbols("invalid dynamic extended section index");
                    }
                }
                else if (extended != null && extended.getInt(index * 4) != 0) {
                    throw new UnsupportedSymbols("nonzero unused dynamic extended section index");
                }
                if (encoded == 0) {
                    continue;
                }
                if (encoded >= 0xff00 && encoded != 0xffff) {
                    if (type == 2 || type == 10) {
                        throw new UnsupportedSymbols("dynamic code symbol uses unsupported reserved index");
                    }
                    rejectHiddenDynamicSymbol(rows, at);
                    continue;
                }
                if (sectionIndex >= image.sections().size()) {
                    throw new UnsupportedSymbols("invalid dynamic symbol section index");
                }
                rejectHiddenDynamicSymbol(rows, at);
                Extent extent = code.get((int) sectionIndex);
                if (extent == null) {
                    continue;
                }
                // FUNC/IFUNC use the ARM instruction-state tag. Other code labels
                // retain their actual value; all defined code types are conservative conflicts.
                long start = type == 2 || type == 10 ? value & ~1L : value;
                if (extent.address() >= UINT32_END || extent.size() > UINT32_END - extent.address() ||
                        start < extent.address() || start - extent.address() > extent.size() ||
                        (size != 0 && !extent.contains(start, size))) {
                    throw new UnsupportedSymbols("dynamic code symbol exceeds its section");
                }
                long end = size == 0 ? Math.addExact(extent.address(), extent.size()) : start + size;
                if (end > start) {
                    addRange(result.computeIfAbsent((int) sectionIndex, unused -> new TreeMap<>()),
                        start, end);
                }
            }
        }
        return result;
    }

    private static void rejectHiddenDynamicSymbol(ByteBuffer rows, int at) {
        // GDB 15.1 skips ordinary dynamic symbols once any static symbol table
        // exists. A partial table would hide definitions even outside our cues,
        // including data and absolute symbols. Undefined imports are handled
        // separately by the consumer and have already been skipped above.
        if (rows.getInt(at) != 0) {
            throw new UnsupportedSymbols("defined dynamic symbols would be hidden by a partial SHT_SYMTAB");
        }
    }

    private static void addRange(TreeMap<Long, Long> ranges, long start, long end) {
        Map.Entry<Long, Long> previous = ranges.floorEntry(start);
        if (previous != null && previous.getValue() >= start) {
            start = previous.getKey();
            end = Math.max(end, previous.getValue());
            ranges.remove(previous.getKey());
        }
        Map.Entry<Long, Long> next = ranges.ceilingEntry(start);
        while (next != null && next.getKey() <= end) {
            end = Math.max(end, next.getValue());
            ranges.remove(next.getKey());
            next = ranges.ceilingEntry(start);
        }
        ranges.put(start, end);
    }

    private static boolean overlaps(TreeMap<Long, Long> ranges, long start, long end) {
        if (ranges == null) {
            return false;
        }
        Map.Entry<Long, Long> previous = ranges.floorEntry(start);
        Map.Entry<Long, Long> next = ranges.ceilingEntry(start);
        return (previous != null && previous.getValue() > start) ||
            (next != null && next.getKey() < end);
    }

    private static String hash(FileChannel input, long offset, long size, ByteBuffer buffer,
            BooleanSupplier cancelled) throws IOException {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        }
        catch (NoSuchAlgorithmException impossible) {
            throw new AssertionError(impossible);
        }
        long done = 0;
        while (done < size) {
            checkCancelled(cancelled);
            buffer.clear().limit((int) Math.min(buffer.capacity(), size - done));
            int count = input.read(buffer, offset + done);
            if (count <= 0) {
                throw new IOException("original code bytes ended or stopped making progress");
            }
            digest.update(buffer.array(), 0, count);
            done += count;
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private static void checkCancelled(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) {
            throw new CancellationException("ARM mode-symbol planning cancelled");
        }
    }
}
