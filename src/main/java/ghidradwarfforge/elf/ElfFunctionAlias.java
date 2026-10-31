package ghidradwarfforge.elf;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;

/** An explicit analyst label with original-code evidence for its complete primary body. */
public record ElfFunctionAlias(String name, String owner, long address, List<CodeRange> ranges) {
    public record CodeRange(long address, long size, String codeSha256) {
        public CodeRange {
            if (address < 0 || size <= 0 || size > Long.MAX_VALUE - address ||
                    codeSha256 == null || !codeSha256.matches("[0-9a-fA-F]{64}")) {
                throw new IllegalArgumentException("invalid alias code range");
            }
            codeSha256 = codeSha256.toLowerCase(Locale.ROOT);
        }

        public boolean contains(long value) {
            return value >= address && value - address < size;
        }
    }

    /** The ordinary entry-first contiguous case remains source-compatible. */
    public ElfFunctionAlias(String name, String owner, long address, long size, String codeSha256) {
        this(name, owner, address, List.of(new CodeRange(address, size, codeSha256)));
    }

    public ElfFunctionAlias {
        if (name == null || name.isBlank() || name.indexOf('\0') >= 0 ||
                name.length() > 65536 || !StandardCharsets.UTF_8.newEncoder().canEncode(name) ||
                name.getBytes(StandardCharsets.UTF_8).length > 65536 ||
                owner == null || owner.isBlank() || name.equals(owner) || address < 0 ||
                ranges == null || ranges.isEmpty() || ranges.size() > 65536) {
            throw new IllegalArgumentException("invalid recovered function alias");
        }
        ranges = List.copyOf(ranges);
        long previousEnd = -1;
        boolean containsEntry = false;
        for (CodeRange range : ranges) {
            if (range.address() < previousEnd) {
                throw new IllegalArgumentException("alias code ranges overlap or are unsorted");
            }
            previousEnd = range.address() + range.size();
            containsEntry |= range.contains(address);
        }
        if (!containsEntry) {
            throw new IllegalArgumentException("alias entry is outside its body");
        }
    }

    /** ELF has one extent: retain only the entry-containing range's suffix, never a gap. */
    public long size() {
        for (CodeRange range : ranges) {
            if (range.contains(address)) {
                return range.size() - (address - range.address());
            }
        }
        throw new AssertionError("validated alias lost its entry range");
    }
}
