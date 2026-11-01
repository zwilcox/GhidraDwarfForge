package ghidradwarfforge.elf;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;

/** ARM ELF function-value tagging, isolated from code and DWARF addresses. */
public final class Arm32FunctionAliasSymbols {
    private static final long UINT32_END = 0x1_0000_0000L;
    private static final long MAX_COMPARISONS = 16L * 1024 * 1024;

    private record Key(String owner, long address, long size, String hash) {
    }

    record Inventory(Map<Integer, TreeMap<Long, Integer>> mappings,
            Map<Integer, TreeMap<Long, Integer>> functionEntries) {
    }

    private Arm32FunctionAliasSymbols() {
    }

    public static List<ElfLocalFunctionSymbol> plan(ElfImage image, List<ElfFunctionAlias> aliases,
            List<FunctionSymbol> functions, List<ElfLocalFunctionSymbol> reserved,
            List<ElfFunctionModeCue> cues, BooleanSupplier cancelled, Consumer<String> diagnostic)
            throws IOException {
        checkCancelled(cancelled);
        if (image.machine() != 40 || image.is64Bit() || image.byteOrder() != ByteOrder.LITTLE_ENDIAN ||
                (image.flags() & 0xff000000L) != 0x05000000L || (image.flags() & 0x00800000L) != 0) {
            diagnostic.accept("Omitted function aliases: ARM mode policy requires little-endian ELF32 EABI5");
            return List.of();
        }
        if (cues.size() > 65536 || (long) aliases.size() * reserved.size() > MAX_COMPARISONS) {
            diagnostic.accept("Omitted function aliases: ARM mode evidence budget exceeded");
            return List.of();
        }
        // Original bytes, complete bodies, ownership, allocation and names are
        // proved while addresses are still ordinary untagged code addresses.
        var planned = FunctionAliasSymbols.plan(image, aliases, functions, reserved, cancelled, diagnostic);
        if (planned.isEmpty()) {
            return List.of();
        }
        Inventory inventory;
        try {
            inventory = inventory(image, cancelled);
        }
        catch (IllegalArgumentException unsupported) {
            diagnostic.accept("Omitted function aliases: ARM original mode inventory: " + unsupported.getMessage());
            return List.of();
        }
        var evidence = new HashMap<Key, ElfFunctionModeCue>();
        var ambiguous = new java.util.HashSet<Key>();
        for (var cue : cues) {
            checkCancelled(cancelled);
            var key = new Key(cue.displayName(), cue.address(), cue.size(), cue.codeSha256());
            if (evidence.putIfAbsent(key, cue) != null) {
                ambiguous.add(key);
            }
        }
        var byName = new HashMap<String, ElfFunctionAlias>();
        for (var alias : aliases) {
            checkCancelled(cancelled);
            byName.put(alias.name(), alias);
        }
        var result = new ArrayList<ElfLocalFunctionSymbol>();
        long comparisons = 0;
        for (var symbol : planned) {
            checkCancelled(cancelled);
            String omission = null;
            try {
                var alias = byName.get(symbol.name());
                var range = alias.ranges().stream().filter(r -> r.contains(alias.address())).findFirst().orElseThrow();
                var key = new Key(alias.owner(), range.address(), range.size(), range.codeSha256());
                var cue = evidence.get(key);
                require(cue != null && !ambiguous.contains(key), "entry range has no unique decoded mode evidence");
                int mode = (int) (cue.symbolValue() & 1);
                require(cue.symbolValue() == (cue.address() | mode) && cue.address() < UINT32_END &&
                    cue.size() <= UINT32_END - cue.address() &&
                    ((cue.address() | cue.size() | alias.address()) & (mode == 0 ? 3 : 1)) == 0,
                    "invalid mode value, extent or instruction alignment");
                long start = alias.address();
                long end = Math.addExact(start, symbol.size());
                var mappings = inventory.mappings().get(symbol.sectionIndex());
                if (mappings != null) {
                    var preceding = mappings.floorEntry(start);
                    require(preceding == null || preceding.getValue() == mode,
                        "original mapping at entry contradicts decoded mode");
                    for (var entry : mappings.subMap(start, true, end, false).entrySet()) {
                        checkCancelled(cancelled);
                        require(++comparisons <= MAX_COMPARISONS, "original mode comparison budget exceeded");
                        require(entry.getValue() == mode, "original mapping changes mode within the alias extent");
                    }
                }
                // A function tag proves its entry mode, not that all bytes in
                // st_size have that mode (veneers may interwork or contain data).
                for (int section : new int[] { symbol.sectionIndex(), -1 }) {
                    var entries = inventory.functionEntries().get(section);
                    if (entries == null) continue;
                    for (var entry : entries.subMap(start, true, end, false).entrySet()) {
                        checkCancelled(cancelled);
                        require(++comparisons <= MAX_COMPARISONS, "original mode comparison budget exceeded");
                        require(entry.getValue() == mode, "original function tag contradicts decoded mode");
                    }
                }
                for (var other : reserved) {
                    checkCancelled(cancelled);
                    long address = other.value() & ~1L;
                    require(other.sectionIndex() != symbol.sectionIndex() || address < start || address >= end ||
                        (other.value() & 1) == mode, "reserved function tag contradicts decoded mode");
                }
                result.add(new ElfLocalFunctionSymbol(symbol.name(), symbol.value() | mode,
                    symbol.size(), symbol.sectionIndex()));
            }
            catch (IllegalArgumentException | ArithmeticException unsupported) {
                omission = unsupported.getMessage();
            }
            if (omission != null) {
                diagnostic.accept("Omitted function alias " + symbol.name() + ": ARM mode policy: " + omission);
            }
        }
        checkCancelled(cancelled);
        return List.copyOf(result);
    }

    static Inventory inventory(ElfImage image, BooleanSupplier cancelled) throws IOException {
        var result = new Inventory(new HashMap<>(), new HashMap<>());
        if (image.sections().isEmpty()) {
            var mirror = DynamicSymbolMirror.read(image, cancelled);
            if (mirror != null) {
                var allocations = ElfLoadAllocations.read(image, cancelled).stream().map(a -> a.section()).toList();
                var sections = new HashMap<Integer, ElfImage.Section>();
                for (var section : allocations) sections.put(section.originalIndex, section);
                collect(result, mirror.records(), mirror.names(), mirror.indices(), sections, cancelled);
            }
            return result;
        }
        long rows = 0;
        long stringBytes = 0;
        var loadedNames = new HashMap<Long, byte[]>();
        var sections = new HashMap<Integer, ElfImage.Section>();
        var extendedSections = new HashMap<Long, ElfImage.Section>();
        for (var section : image.sections()) {
            checkCancelled(cancelled);
            sections.put(section.originalIndex, section);
            if (section.type == 18) {
                require(extendedSections.putIfAbsent(section.link, section) == null,
                    "duplicate extended symbol indices");
            }
        }
        for (var table : image.sections()) {
            checkCancelled(cancelled);
            if (table.type != 2 && table.type != 11) continue;
            require(table.entrySize == 16 && table.size >= 16 && table.size % 16 == 0 &&
                (rows += table.size / 16) <= 262144 && (table.flags & 0x800) == 0 &&
                table.link > 0 && table.link < image.sections().size(), "unsupported symbol table framing");
            byte[] names = loadedNames.get(table.link);
            if (names == null) {
                var strings = image.sections().get((int) table.link);
                require(strings.type == 3 && strings.size > 0 && (strings.flags & 0x800) == 0 &&
                    strings.size <= 16L * 1024 * 1024 - stringBytes, "unsupported string inventory");
                stringBytes += strings.size;
                names = image.sectionData(strings);
                loadedNames.put(table.link, names);
            }
            byte[] indices = null;
            var candidate = extendedSections.get((long) table.originalIndex);
            if (candidate != null) {
                require(candidate.size == table.size / 4 && candidate.entrySize == 4 &&
                    candidate.info == 0 && (candidate.flags & 0x800) == 0, "unsupported extended symbol indices");
                indices = image.sectionData(candidate);
            }
            collect(result, image.sectionData(table), names, indices, sections, cancelled);
        }
        return result;
    }

    private static void collect(Inventory inventory, byte[] records, byte[] names, byte[] indices,
            Map<Integer, ElfImage.Section> sections, BooleanSupplier cancelled) {
        var bytes = ByteBuffer.wrap(records).order(ByteOrder.LITTLE_ENDIAN);
        var extended = indices == null ? null : ByteBuffer.wrap(indices).order(ByteOrder.LITTLE_ENDIAN);
        for (int offset = 0; offset < records.length; offset += 16) {
            checkCancelled(cancelled);
            long name = Integer.toUnsignedLong(bytes.getInt(offset));
            long value = Integer.toUnsignedLong(bytes.getInt(offset + 4));
            long size = Integer.toUnsignedLong(bytes.getInt(offset + 8));
            int info = Byte.toUnsignedInt(records[offset + 12]);
            int other = Byte.toUnsignedInt(records[offset + 13]);
            int sectionIndex = Short.toUnsignedInt(bytes.getShort(offset + 14));
            if (sectionIndex == 0) continue;
            if (sectionIndex == 0xffff) {
                require(extended != null, "missing extended symbol index");
                long index = Integer.toUnsignedLong(extended.getInt(offset / 4));
                require(index > 0 && index <= Integer.MAX_VALUE, "invalid extended symbol index");
                sectionIndex = (int) index;
            }
            require(name < names.length, "symbol name offset is out of bounds");
            int mapping = -1;
            if (names[(int) name] == '$' && name + 2 < names.length &&
                    (names[(int) name + 2] == 0 || names[(int) name + 2] == '.')) {
                mapping = switch (names[(int) name + 1]) {
                    case 'a' -> 0;
                    case 't' -> 1;
                    case 'd' -> 2;
                    default -> -1;
                };
            }
            int type = info & 15;
            var section = sections.get(sectionIndex);
            if (mapping >= 0) {
                require(info == 0 && size == 0 && other == 0 && section != null &&
                    value >= section.address && value - section.address <= section.size,
                    "malformed mapping symbol");
                if ((section.flags & 6) == 6) {
                    put(inventory.mappings(), sectionIndex, value, mapping);
                }
            }
            else if (type == 2 || type >= 10) {
                require(type == 2 && (other & ~3) == 0, "unverified code symbol type or mode flags");
                if (section == null && sectionIndex != 0xfff1) continue;
                if (section != null && (section.flags & 6) != 6) continue;
                long address = value & ~1L;
                int mode = (int) (value & 1);
                require((address & (mode == 0 ? 3 : 1)) == 0, "unaligned original function tag");
                require(section == null || (address >= section.address && address - section.address < section.size),
                    "original function entry is outside its executable section");
                put(inventory.functionEntries(), section == null ? -1 : sectionIndex, address, mode);
            }
        }
    }

    private static void put(Map<Integer, TreeMap<Long, Integer>> inventory, int section, long address, int mode) {
        Integer old = inventory.computeIfAbsent(section, ignored -> new TreeMap<>()).putIfAbsent(address, mode);
        require(old == null || old == mode, "conflicting original mode evidence at one address");
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new IllegalArgumentException(message);
    }

    private static void checkCancelled(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("ARM alias mode planning cancelled");
    }
}
