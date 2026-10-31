package ghidradwarfforge.elf;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/** Shared, ordered synthetic section identities for inputs without a section table. */
final class ElfLoadAllocations {
    record Allocation(ElfImage.Section section, long fileSize) {
    }

    private ElfLoadAllocations() {
    }

    static List<Allocation> read(ElfImage image, BooleanSupplier cancelled) {
        List<Allocation> allocations = new ArrayList<>();
        for (int index = 0; index < image.segments().size(); index++) {
            if (cancelled.getAsBoolean()) {
                throw new CancellationException("ELF load allocation inventory cancelled");
            }
            var segment = image.segments().get(index);
            if (segment.type != 1 || segment.memorySize == 0) {
                continue;
            }
            long end;
            try {
                end = Math.addExact(segment.virtualAddress, segment.memorySize);
            }
            catch (ArithmeticException overflow) {
                throw new IllegalArgumentException("PT_LOAD virtual range exceeds signed 64-bit addresses at " + index,
                    overflow);
            }
            if (!image.is64Bit() && end > 0x1_0000_0000L) {
                throw new IllegalArgumentException("PT_LOAD virtual range exceeds ELF32 address space at " + index);
            }
            var section = new ElfImage.Section();
            section.originalIndex = allocations.size() + 1;
            section.name = ".forge.load." + index;
            section.type = 8; // Inert SHT_NOBITS metadata, not recovered original sections.
            section.flags = 2 | ((segment.flags & 2) != 0 ? 1 : 0) | ((segment.flags & 1) != 0 ? 4 : 0);
            section.address = segment.virtualAddress;
            section.offset = segment.offset;
            section.size = segment.memorySize;
            // Segment alignment constrains VA/file congruence, not section VA alignment.
            section.alignment = 1;
            allocations.add(new Allocation(section, segment.fileSize));
        }
        return List.copyOf(allocations);
    }
}
