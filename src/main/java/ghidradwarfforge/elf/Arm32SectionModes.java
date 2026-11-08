package ghidradwarfforge.elf;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.TreeMap;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/** Complete allocation mapping; an unknown gap cannot be represented by a sized boundary. */
public final class Arm32SectionModes {
    public record Allocation(int index, String name, long address, long size, long fileSize, long fileOffset) { }
    /** Mode is ARM=0, Thumb=1, data=2; offset is relative to the complete allocation. */
    public record Boundary(long offset, int mode) { }
    public record Evidence(int sectionIndex, long address, long size, String sha256, List<Boundary> boundaries) {
        public Evidence {
            boundaries = List.copyOf(boundaries);
            if (sectionIndex <= 0 || address < 0 || size <= 0 || address >= 0x1_0000_0000L ||
                    size > 0x1_0000_0000L - address || sha256 == null || !sha256.matches("[0-9a-f]{64}") ||
                    boundaries.isEmpty() || boundaries.size() > 65536 || boundaries.getFirst().offset() != 0) {
                throw new IllegalArgumentException("invalid complete ARM section evidence");
            }
            long previous = -1;
            int priorMode = -1;
            for (var boundary : boundaries) {
                if (boundary.offset() <= previous || boundary.offset() >= size || boundary.mode() < 0 ||
                        boundary.mode() > 2 || boundary.mode() == priorMode) {
                    throw new IllegalArgumentException("invalid ARM section boundary sequence");
                }
                previous = boundary.offset();
                priorMode = boundary.mode();
            }
        }
    }

    private Arm32SectionModes() { }

    public static List<Allocation> allocations(ElfImage image, BooleanSupplier cancelled) {
        var result = new ArrayList<Allocation>();
        var inputs = image.sections().isEmpty() ? ElfLoadAllocations.read(image, cancelled) :
            image.sections().stream().map(s -> new ElfLoadAllocations.Allocation(s, s.type == 1 ? s.size : 0)).toList();
        for (var input : inputs) {
            check(cancelled);
            var s = input.section();
            if ((s.flags & 6) == 6 && (s.flags & 0x800) == 0 && s.size > 0) {
                result.add(new Allocation(s.originalIndex, s.name, s.address, s.size, input.fileSize(), s.offset));
            }
        }
        return List.copyOf(result);
    }

    public static List<ElfLocalMappingSymbol> plan(ElfImage image, List<Evidence> evidence,
            List<ElfLocalFunctionSymbol> reserved, BooleanSupplier cancelled, Consumer<String> diagnostic)
            throws IOException {
        check(cancelled);
        if (evidence.isEmpty()) return List.of();
        if (image.machine() != 40 || image.is64Bit() || image.byteOrder() != ByteOrder.LITTLE_ENDIAN ||
                (image.flags() & 0xff000000L) != 0x05000000L || (image.flags() & 0x00800000L) != 0 ||
                (image.type() != 2 && image.type() != 3)) {
            diagnostic.accept("Omitted ARM32 section mappings: requires little-endian ELF32 EABI5 ET_EXEC/ET_DYN");
            return List.of();
        }
        long boundaries = evidence.stream().mapToLong(e -> e.boundaries().size()).sum();
        var allocations = allocations(image, cancelled);
        var allAllocated = image.sections().isEmpty()
            ? ElfLoadAllocations.read(image, cancelled).stream().map(ElfLoadAllocations.Allocation::section).toList()
            : image.sections().stream().filter(section -> (section.flags & 2) != 0 && section.size != 0).toList();
        if (boundaries > 65536L - reserved.size() || (long) evidence.size() * (allAllocated.size() + reserved.size()) > 16L * 1024 * 1024) {
            diagnostic.accept("Omitted ARM32 section mappings: comparison or symbol budget exceeded");
            return List.of();
        }
        var result = new ArrayList<ElfLocalMappingSymbol>();
        java.util.Set<ByteBuffer> occupied;
        Arm32FunctionAliasSymbols.Inventory original;
        try {
            occupied = FunctionAliasSymbols.originalNames(image, cancelled, diagnostic);
            original = Arm32FunctionAliasSymbols.inventory(image, cancelled);
        }
        catch (IllegalArgumentException unsupported) {
            diagnostic.accept("Omitted ARM32 section mappings: original symbol inventory: " + unsupported.getMessage());
            return List.of();
        }
        var reservedNames = new HashSet<String>();
        reserved.forEach(s -> reservedNames.add(s.name()));
        var seen = new HashSet<Integer>();
        var duplicates = new HashSet<Integer>();
        evidence.forEach(e -> { if (!seen.add(e.sectionIndex())) duplicates.add(e.sectionIndex()); });
        long comparedBytes = 0;
        try (var input = FileChannel.open(image.sourcePath(), StandardOpenOption.READ)) {
            image.requireUnchanged(input);
            for (var item : evidence.stream().sorted(Comparator.comparingInt(Evidence::sectionIndex)).toList()) {
                check(cancelled);
                try {
                    require(!duplicates.contains(item.sectionIndex()), "duplicate section evidence");
                    var matching = allocations.stream().filter(a -> a.index() == item.sectionIndex()).toList();
                    require(matching.size() == 1, "missing unique executable allocation");
                    var allocation = matching.getFirst();
                    require(allocation.address() == item.address() && allocation.size() == item.size() &&
                        allocation.fileSize() == item.size(), "allocation extent or file backing disagrees");
                    for (var other : allAllocated) {
                        check(cancelled);
                        require(other.originalIndex == allocation.index() ||
                            (other.address < item.address() ? item.address() - other.address >= other.size :
                                other.address - item.address() >= item.size()), "overlapping allocated sections");
                    }
                    require(item.size() <= 256L * 1024 * 1024 - comparedBytes, "mapping byte budget exceeded");
                    comparedBytes += item.size();
                    require(FunctionAliasSymbols.hash(input, allocation.fileOffset(), item.size(), cancelled)
                        .equals(item.sha256()), "listing bytes differ from original ELF");
                    var modes = new TreeMap<Long, Integer>();
                    for (int i = 0; i < item.boundaries().size(); i++) {
                        check(cancelled);
                        var b = item.boundaries().get(i);
                        long end = i + 1 == item.boundaries().size() ? item.size() : item.boundaries().get(i + 1).offset();
                        int mask = b.mode() == 0 ? 3 : b.mode() == 1 ? 1 : 0;
                        require(((item.address() + b.offset()) & mask) == 0 && ((end - b.offset()) & mask) == 0,
                            "unaligned code mapping extent");
                        modes.put(item.address() + b.offset(), b.mode());
                    }
                    var old = original.mappings().get(item.sectionIndex());
                    if (old != null) {
                        for (var b : old.entrySet()) {
                            check(cancelled);
                            if (b.getKey() == item.address() + item.size()) continue;
                            require(modes.floorEntry(b.getKey()) != null &&
                                modes.floorEntry(b.getKey()).getValue().equals(b.getValue()),
                                "inherited mapping contradicts listing");
                        }
                        for (var b : modes.entrySet()) {
                            check(cancelled);
                            var inherited = old.floorEntry(b.getKey());
                            require(inherited == null || inherited.getValue().equals(b.getValue()),
                                "inherited mapping interval contradicts listing");
                        }
                    }
                    for (int key : new int[] { item.sectionIndex(), -1 }) {
                        var entries = original.functionEntries().get(key);
                        if (entries == null) continue;
                        for (var entry : entries.subMap(item.address(), true, item.address() + item.size(), false).entrySet()) {
                            check(cancelled);
                            require(modes.floorEntry(entry.getKey()).getValue().equals(entry.getValue()),
                                "inherited function tag contradicts listing");
                        }
                    }
                    for (var function : reserved) {
                        check(cancelled);
                        if (function.sectionIndex() != item.sectionIndex()) continue;
                        var mode = modes.floorEntry(function.value() & ~1L);
                        require(mode != null && mode.getValue() == (function.value() & 1),
                            "supplemental function tag contradicts listing");
                    }
                    var additions = new ArrayList<ElfLocalMappingSymbol>();
                    for (var b : modes.entrySet()) {
                        check(cancelled);
                        if (old != null && old.containsKey(b.getKey())) continue;
                        char tag = "atd".charAt(b.getValue());
                        String name = String.format(Locale.ROOT, "$%c.forge_%x_%08x", tag, item.sectionIndex(), b.getKey());
                        require(!reservedNames.contains(name) && !occupied.contains(ByteBuffer.wrap(name.getBytes(StandardCharsets.UTF_8))),
                            "mapping name conflicts with existing symbol");
                        additions.add(new ElfLocalMappingSymbol(name, b.getKey(), item.sectionIndex()));
                    }
                    result.addAll(additions);
                }
                catch (Omitted unsupported) {
                    diagnostic.accept("Omitted ARM32 section mappings for section " + item.sectionIndex() + ": " + unsupported.getMessage());
                }
            }
            image.requireUnchanged(input);
        }
        check(cancelled);
        return List.copyOf(result);
    }

    private static final class Omitted extends RuntimeException {
        Omitted(String message) { super(message); }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new Omitted(message);
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("ARM section mapping cancelled");
    }
}
