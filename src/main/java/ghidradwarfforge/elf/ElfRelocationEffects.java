package ghidradwarfforge.elf;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

import ghidradwarfforge.targets.UnwindRelocationProfile;

/** Declared loader write footprints for selected ordinary ABIs; never evaluates a relocation. */
public final class ElfRelocationEffects {
    public record Write(String role, long recordOffset, long type, long symbol, long address,
            long size, long fileOffset, long fileBytes) { }
    private record Region(long address, long size, boolean dynamic) { }
    private record Pending(String role, long recordOffset, long type, long symbol, long address, long size) { }
    private static final Set<Long> SEGMENTS = Set.of(0L, 1L, 2L, 3L, 4L, 6L, 7L,
        0x6474e550L, 0x6474e551L, 0x6474e552L, 0x6474e553L);
    private final String profile;
    private final List<Write> writes;
    private final long[] ends;
    private ElfRelocationEffects(String profile, List<Write> writes, long[] ends) {
        this.profile = profile; this.writes = List.copyOf(writes); this.ends = ends;
    }
    public String profile() { return profile; }
    public List<Write> writes() { return writes; }

    public static ElfRelocationEffects inspect(ElfImage image, BooleanSupplier cancelled) throws IOException {
        check(cancelled);
        var profile = UnwindRelocationProfile.select(image);
        int addressBytes = image.is64Bit() ? 8 : 4;
        var inventory = ElfRuntimeRelocations.inspect(image, cancelled);
        var tags = new HashMap<Long, Long>();
        for (var tag : inventory.tags()) {
            check(cancelled); profile.requireTag(tag.tag(), tag.value());
            require(tag.tag() == 1 || tags.putIfAbsent(tag.tag(), tag.value()) == null,
                "duplicate ordinary loader metadata");
        }
        // REL[A]COUNT permits loaders to process a prefix without dispatching
        // on each record's type. A contradictory count is not ordinary evidence.
        for (long tag : List.of(0x6ffffff9L, 0x6ffffffaL)) {
            if (!tags.containsKey(tag)) continue;
            long count = tags.get(tag);
            String role = tag == 0x6ffffff9L ? "DT_RELA" : "DT_REL";
            var table = inventory.tables().stream().filter(candidate -> candidate.role().equals(role)).findFirst();
            require(count >= 0 && (count == 0 || table.isPresent() && count <= table.get().relocations().size()),
                "relative relocation prefix count exceeds its table");
            for (int index = 0; index < count; index++) {
                check(cancelled);
                long info = table.orElseThrow().relocations().get(index).info();
                require(info == profile.relativeType(), "relative relocation prefix contains a non-relative record");
            }
        }
        var metadata = new ArrayList<Region>();
        for (var segment : image.segments()) {
            check(cancelled);
            require(SEGMENTS.contains(segment.type), "unreviewed program-header loader/unwind extension");
            if (segment.type == 2) metadata.add(new Region(segment.virtualAddress, segment.fileSize, true));
        }
        for (var table : inventory.tables()) metadata.add(new Region(table.address(), table.size(), false));
        for (var section : image.sections()) {
            check(cancelled);
            require(!section.name.equals(".sframe") || section.size == 0, "original SFrame coverage is not qualified");
        }
        boolean needsSymbols = false;
        for (var table : inventory.tables()) for (var row : table.relocations()) {
            check(cancelled);
            if (row.info() != null && relocationType(image, row.info()) != 0 && relocationSymbol(image, row.info()) != 0) needsSymbols = true;
        }
        var symbols = needsSymbols ? SectionlessDynamicSymbols.originalRecords(image, cancelled) :
            List.<SectionlessDynamicSymbols.RawSymbol>of();
        if (needsSymbols) metadata.add(new Region(tags.get(6L), (long) symbols.size() * (image.is64Bit() ? 24 : 16), false));
        var pending = new ArrayList<Pending>();
        var loadBounds = ElfLoadAllocations.read(image, cancelled);
        long comparisons = 0;
        boolean textrel = tags.containsKey(22L) || (tags.getOrDefault(30L, 0L) & 4) != 0;
        for (var table : inventory.tables()) for (var row : table.relocations()) {
            check(cancelled);
            long type = row.info() == null ? -1 : relocationType(image, row.info());
            long symbol = row.info() == null ? 0 : relocationSymbol(image, row.info());
            if (type == 0) continue;
            require(type != profile.indirectType(), "indirect relocation resolver has unproved effects");
            long size;
            Integer fixed = profile.fixedWidths().get(type);
            require(type == -1 || type == profile.copyType() || fixed != null,
                "unsupported runtime relocation type " + type + " for " + profile.id());
            if (symbol != 0) {
                require(symbol < symbols.size(), "relocation symbol index exceeds established table");
                require((symbols.get((int) symbol).info() & 15) != 10,
                    "IFUNC symbol resolver has unproved effects");
            }
            if (type == profile.copyType()) {
                // Linux toolchains also emit COPY in PIE executables. Require
                // both the executable dynamic flag and interpreter for ET_DYN.
                boolean executable = image.type() == 2 ||
                    ((tags.getOrDefault(0x6ffffffbL, 0L) & 0x08000000L) != 0 &&
                        image.segments().stream().anyMatch(segment -> segment.type == 3));
                require(executable && symbol != 0, "COPY relocation is outside the audited executable contract");
                var entry = symbols.get((int) symbol);
                require((entry.info() & 15) <= 1 && (entry.info() >>> 4 == 1 || entry.info() >>> 4 == 2) &&
                    entry.section() > 0 && entry.section() < 0xff00 && entry.value() == row.address(),
                    "COPY relocation lacks a matching ordinary defined object");
                size = entry.size();
            }
            else {
                size = type == -1 ? addressBytes : fixed.longValue();
                require(row.address() % profile.alignment() == 0,
                    "relocation destination violates the selected ABI alignment");
            }
            pending.add(new Pending(table.role(), row.recordOffset(), type, symbol, row.address(), size));
        }
        // The ordinary loader also writes these declared metadata destinations
        // without an explicit relocation record. Conservatively include them
        // even when eager binding makes a reserved slot unnecessary.
        for (var pointer : profile.loaderPointerWrites()) {
            check(cancelled);
            if (tags.containsKey(pointer.tag())) pending.add(new Pending("loader-tag-" + Long.toHexString(pointer.tag()),
                -1, -2, 0, add(tags.get(pointer.tag()), pointer.offset()), pointer.size()));
        }
        if (tags.containsKey(21L)) {
            var dynamic = image.segments().stream().filter(segment -> segment.type == 2).findFirst().orElseThrow();
            for (int index = 0; index < inventory.tags().size(); index++) {
                check(cancelled);
                if (inventory.tags().get(index).tag() == 21) {
                    long delta = (long) index * addressBytes * 2 + addressBytes;
                    pending.add(new Pending("loader-DT_DEBUG", add(dynamic.offset, delta), -2, 0,
                        add(dynamic.virtualAddress, delta), addressBytes));
                }
            }
        }
        var writes = new ArrayList<Write>();
        for (var row : pending) {
            check(cancelled);
            long size = row.size();
            if (size == 0) continue;
            long end = add(row.address(), size);
            ElfLoadAllocations.Allocation selected = null;
            for (var load : loadBounds) {
                check(cancelled);
                require(++comparisons <= 16L * 1024 * 1024, "relocation effect mapping budget exceeded");
                var section = load.section();
                if (row.address() < add(section.address, section.size) && section.address < end) {
                    require(selected == null, "relocation destination has ambiguous load mappings"); selected = load;
                }
            }
            require(selected != null && row.address() >= selected.section().address &&
                end <= add(selected.section().address, selected.section().size),
                "relocation write exceeds one allocated load extent");
            require((selected.section().flags & 1) != 0 || textrel,
                "relocation targets non-writable storage without text-relocation metadata");
            for (var region : metadata) {
                check(cancelled);
                require(++comparisons <= 16L * 1024 * 1024, "relocation effect mapping budget exceeded");
                if (region.dynamic() && row.role().equals("loader-DT_DEBUG")) continue;
                require(region.size() == 0 || end <= region.address() ||
                    row.address() >= add(region.address(), region.size()),
                    "relocation may rewrite relocation/symbol metadata");
            }
            long delta = row.address() - selected.section().address;
            long fileBytes = Math.min(size, Math.max(0, selected.fileSize() - delta));
            writes.add(new Write(row.role(), row.recordOffset(), row.type(), row.symbol(), row.address(), size,
                fileBytes == 0 ? -1 : add(selected.section().offset, delta), fileBytes));
        }
        writes.sort(Comparator.comparingLong(Write::address).thenComparingLong(Write::recordOffset));
        var ends = new long[writes.size()];
        for (int i = 0; i < writes.size(); i++) {
            check(cancelled); ends[i] = Math.max(i == 0 ? 0 : ends[i - 1], add(writes.get(i).address(), writes.get(i).size()));
        }
        check(cancelled);
        try (var channel = FileChannel.open(image.sourcePath(), StandardOpenOption.READ)) { image.requireUnchanged(channel); }
        return new ElfRelocationEffects(profile.id(), writes, ends);
    }

    /** Use original link-time VAs; a code region must not overlap a declared loader write. */
    public void requireUnchanged(long address, long size, BooleanSupplier cancelled) {
        check(cancelled); require(address >= 0 && size > 0, "invalid protected address extent");
        long end = add(address, size);
        int low = 0, high = writes.size();
        while (low < high) {
            check(cancelled); int middle = (low + high) >>> 1;
            if (writes.get(middle).address() < end) low = middle + 1; else high = middle;
        }
        require(low == 0 || ends[low - 1] <= address, "protected interval overlaps a runtime relocation write");
    }

    /** Protect file-derived frame records, including any file-backed load aliases. */
    public void requireUnchanged(OriginalFrameSources.Inventory inventory, BooleanSupplier cancelled) {
        check(cancelled);
        for (var source : inventory.sources()) requireFileUnchanged(source.offset(), source.storedBytes(), cancelled);
    }

    public void requireFileUnchanged(long offset, long size, BooleanSupplier cancelled) {
        check(cancelled);
        long end = add(offset, size);
        for (var write : writes) {
            check(cancelled);
            require(size == 0 || write.fileBytes() == 0 || end <= write.fileOffset() ||
                offset >= add(write.fileOffset(), write.fileBytes()),
                "original frame source overlaps a runtime relocation write");
        }
    }
    private static long relocationType(ElfImage image, long info) {
        return info & (image.is64Bit() ? 0xffff_ffffL : 0xffL);
    }
    private static long relocationSymbol(ElfImage image, long info) {
        return info >>> (image.is64Bit() ? 32 : 8);
    }
    private static long add(long a, long b) {
        require(a >= 0 && b >= 0, "negative relocation extent");
        try { return Math.addExact(a, b); }
        catch (ArithmeticException overflow) { throw new IllegalArgumentException("relocation write extent overflows", overflow); }
    }
    private static void require(boolean condition, String message) {
        if (!condition) throw new IllegalArgumentException(message);
    }
    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("relocation effects cancelled");
    }
}
