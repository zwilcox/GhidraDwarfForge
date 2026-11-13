package ghidradwarfforge.firmware;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Explicit runtime allocations and original-file provenance in one flat address space.
 * No image-base subtraction, guessed zero filling, or implicit aliasing occurs here.
 * Addresses use the exporter's existing nonnegative signed-64-bit range model.
 */
public record FirmwareMemoryMap(int addressBits, List<Input> inputs, List<Region> regions) {
    public enum Storage { FILE_BACKED, UNINITIALIZED }

    /** Logical input identity; filenames alone are never evidence of matching bytes. */
    public record Input(String id, long size, String sha256) {
        public Input {
            requireName(id, "input ID");
            if (size <= 0 || sha256 == null || !sha256.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("input requires positive size and SHA-256");
            }
        }
    }

    /** A contiguous portion of a region, with an absolute offset in an original input. */
    public record FileSpan(long regionOffset, long length, String inputId, long fileOffset) {
        public FileSpan {
            requireName(inputId, "span input ID");
            end(regionOffset, length, "region span");
            end(fileOffset, length, "input span");
        }
    }

    /** Uninitialized means unknown contents, not proof of zero-filled BSS or device semantics. */
    public record Region(String name, long address, long length,
            boolean read, boolean write, boolean execute, Storage storage, List<FileSpan> spans) {
        public Region {
            requireName(name, "region name");
            end(address, length, "region");
            Objects.requireNonNull(storage, "region storage");
            var ordered = new ArrayList<>(spans);
            ordered.sort(Comparator.comparingLong(FileSpan::regionOffset));
            spans = List.copyOf(ordered);
            if (storage == Storage.UNINITIALIZED) {
                if (!spans.isEmpty()) {
                    throw new IllegalArgumentException("uninitialized region cannot claim input bytes: " + name);
                }
            }
            else {
                long next = 0;
                for (FileSpan span : spans) {
                    if (span.regionOffset() != next) {
                        throw new IllegalArgumentException("file provenance has a gap or overlap: " + name);
                    }
                    next = end(next, span.length(), "provenance extent");
                }
                if (next != length) {
                    throw new IllegalArgumentException("file provenance does not cover region: " + name);
                }
            }
        }

        public long endExclusive() { return end(address, length, "region"); }
    }

    public FirmwareMemoryMap {
        if (addressBits != 32 && addressBits != 64) {
            throw new IllegalArgumentException("firmware address width must be 32 or 64");
        }
        var orderedInputs = new ArrayList<>(inputs);
        orderedInputs.sort(Comparator.comparing(Input::id));
        inputs = List.copyOf(orderedInputs);
        if (inputs.isEmpty()) throw new IllegalArgumentException("firmware map requires original inputs");
        Map<String, Input> byId = new HashMap<>();
        for (Input input : inputs) {
            if (byId.putIfAbsent(input.id(), input) != null) {
                throw new IllegalArgumentException("duplicate firmware input ID: " + input.id());
            }
        }
        var orderedRegions = new ArrayList<>(regions);
        orderedRegions.sort(Comparator.comparingLong(Region::address).thenComparing(Region::name));
        regions = List.copyOf(orderedRegions);
        if (regions.isEmpty()) throw new IllegalArgumentException("firmware map requires memory regions");
        var names = new HashSet<String>();
        var usedInputs = new HashSet<String>();
        long previousEnd = 0;
        for (Region region : regions) {
            if (!names.add(region.name())) {
                throw new IllegalArgumentException("duplicate firmware region name: " + region.name());
            }
            long limit = region.endExclusive();
            if (region.address() < previousEnd) {
                throw new IllegalArgumentException("overlapping firmware runtime regions: " + region.name());
            }
            if (addressBits == 32 && limit > 0x1_0000_0000L) {
                throw new IllegalArgumentException("firmware region exceeds 32-bit address space: " + region.name());
            }
            previousEnd = limit;
            for (FileSpan span : region.spans()) {
                Input input = byId.get(span.inputId());
                if (input == null || end(span.fileOffset(), span.length(), "input span") > input.size()) {
                    throw new IllegalArgumentException("firmware provenance references missing or short input: " + span.inputId());
                }
                usedInputs.add(input.id());
            }
        }
        if (!usedInputs.equals(byId.keySet())) {
            throw new IllegalArgumentException("firmware map contains an input with no mapped bytes");
        }
    }

    private static long end(long start, long length, String what) {
        if (start < 0 || length <= 0 || start > Long.MAX_VALUE - length) {
            throw new IllegalArgumentException(what + " exceeds supported address/offset range");
        }
        return start + length;
    }

    private static void requireName(String name, String what) {
        if (name == null || name.isBlank() || name.indexOf('\0') >= 0 ||
                !java.nio.charset.StandardCharsets.UTF_8.newEncoder().canEncode(name)) {
            throw new IllegalArgumentException("invalid firmware " + what);
        }
    }
}
