package ghidradwarfforge.locations;

import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Native-independent variable storage and live-range model. Stack offsets are
 * retained in Ghidra's function-stack coordinate system until a defensible
 * target frame-base policy is available; they are not implicitly DWARF
 * {@code DW_OP_fbreg} offsets.
 */
public record VariableStorageModel(List<VariableLocation> variables) {
    public enum VariableKind {
        PARAMETER, LOCAL
    }

    public enum Confidence {
        USER_DEFINED, IMPORTED, ANALYSIS, DECOMPILER
    }

    public enum OmissionReason {
        UNASSIGNED, OPTIMIZED_AWAY, UNMAPPED_REGISTER, UNSUPPORTED_STORAGE,
        UNKNOWN_LIFETIME, REGISTER_MODIFIED, CALL_CLOBBERED
    }

    /** A target-specific, already verified Ghidra-to-DWARF register mapping. */
    public record DwarfRegister(String ghidraName, int dwarfNumber) {
        public DwarfRegister {
            requireText(ghidraName, "Ghidra register name");
            if (dwarfNumber < 0) {
                throw new IllegalArgumentException("DWARF register number must be nonnegative");
            }
        }
    }

    public sealed interface Storage permits StackStorage, RegisterStorage,
            RegisterRelativeStorage, MemoryStorage, CompositeStorage,
            UnavailableStorage {
        default boolean available() {
            return !(this instanceof UnavailableStorage);
        }
    }

    /** Offset in Ghidra's function-stack coordinate system. */
    public record StackStorage(long byteOffset) implements Storage {
    }

    /** A register or an explicitly described slice of its value. */
    public record RegisterStorage(DwarfRegister register, int valueBitOffset,
            int bitSize) implements Storage {
        public RegisterStorage {
            if (register == null || valueBitOffset < 0 || bitSize <= 0) {
                throw new IllegalArgumentException("invalid register storage");
            }
        }
    }

    /** Memory addressed by a mapped target register plus a signed byte offset. */
    public record RegisterRelativeStorage(DwarfRegister register,
            long byteOffset) implements Storage {
        public RegisterRelativeStorage {
            if (register == null) {
                throw new IllegalArgumentException("register-relative base is required");
            }
        }
    }

    /** Absolute link-time memory address, retained independently of encoding. */
    public record MemoryStorage(long address) implements Storage {
        public MemoryStorage {
            if (address < 0) {
                throw new IllegalArgumentException("memory address must be nonnegative");
            }
        }
    }

    public record Piece(Storage storage, int bitSize) {
        public Piece {
            if (storage == null || !storage.available() ||
                    storage instanceof CompositeStorage || bitSize <= 0) {
                throw new IllegalArgumentException("invalid composite-storage piece");
            }
        }
    }

    public record CompositeStorage(List<Piece> pieces) implements Storage {
        public CompositeStorage {
            if (pieces == null || pieces.isEmpty()) {
                throw new IllegalArgumentException("composite storage requires pieces");
            }
            pieces = List.copyOf(pieces);
        }

        public long totalBitSize() {
            long total = 0;
            for (Piece piece : pieces) {
                total = Math.addExact(total, piece.bitSize());
            }
            return total;
        }
    }

    public record UnavailableStorage(OmissionReason reason,
            String diagnostic) implements Storage {
        public UnavailableStorage {
            if (reason == null) {
                throw new IllegalArgumentException("omission reason is required");
            }
            requireText(diagnostic, "omission diagnostic");
        }
    }

    public record Evidence(Confidence confidence, String source) {
        public Evidence {
            if (confidence == null) {
                throw new IllegalArgumentException("storage confidence is required");
            }
            requireText(source, "storage evidence source");
        }
    }

    /** Half-open link-time address range over which one storage is defensible. */
    public record LocationRange(long start, long end, Storage storage,
            Evidence evidence) {
        public LocationRange {
            if (start < 0 || end <= start || storage == null || evidence == null) {
                throw new IllegalArgumentException("invalid variable location range");
            }
        }
    }

    public record VariableLocation(String functionName, long functionAddress,
            String name, VariableKind kind, long byteSize,
            List<LocationRange> locations) {
        public VariableLocation {
            requireText(functionName, "containing function name");
            requireText(name, "variable name");
            if (functionAddress < 0 || kind == null || byteSize <= 0 ||
                    locations == null || locations.isEmpty()) {
                throw new IllegalArgumentException("invalid variable location");
            }
            locations = locations.stream()
                .sorted(Comparator.comparingLong(LocationRange::start)
                    .thenComparingLong(LocationRange::end))
                .toList();
            long previousEnd = -1;
            long expectedBits = Math.multiplyExact(byteSize, 8L);
            for (LocationRange location : locations) {
                if (location.start() < previousEnd) {
                    throw new IllegalArgumentException(
                        "overlapping location ranges for " + name);
                }
                previousEnd = location.end();
                if (location.storage() instanceof CompositeStorage composite &&
                        composite.totalBitSize() != expectedBits) {
                    throw new IllegalArgumentException(
                        "composite storage does not cover all bits of " + name);
                }
            }
        }

        public boolean hasDefensibleLocation() {
            return locations.stream().anyMatch(location -> location.storage().available());
        }

        public boolean changesLocation() {
            return locations.stream().map(LocationRange::storage).distinct().count() > 1;
        }
    }

    public VariableStorageModel {
        if (variables == null) {
            throw new IllegalArgumentException("variable locations are required");
        }
        variables = variables.stream()
            .sorted(Comparator.comparingLong(VariableLocation::functionAddress)
                .thenComparing(VariableLocation::kind)
                .thenComparing(VariableLocation::name))
            .toList();
        Set<String> keys = new HashSet<>();
        for (VariableLocation variable : variables) {
            String key = variable.functionAddress() + "\u0000" + variable.kind() +
                "\u0000" + variable.name();
            if (!keys.add(key)) {
                throw new IllegalArgumentException("duplicate variable location " +
                    variable.functionName() + "::" + variable.name());
            }
        }
    }

    private static void requireText(String value, String description) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(description + " is required");
        }
    }
}
