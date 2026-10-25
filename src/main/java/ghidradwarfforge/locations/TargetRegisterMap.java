package ghidradwarfforge.locations;

import java.io.IOException;
import java.nio.ByteOrder;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.BooleanSupplier;

import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.elf.MipsAbiFlags;

import ghidradwarfforge.locations.VariableStorageModel.DwarfRegister;
import ghidradwarfforge.locations.VariableStorageModel.OmissionReason;
import ghidradwarfforge.locations.VariableStorageModel.RegisterRelativeStorage;
import ghidradwarfforge.locations.VariableStorageModel.RegisterStorage;
import ghidradwarfforge.locations.VariableStorageModel.Storage;
import ghidradwarfforge.locations.VariableStorageModel.UnavailableStorage;

/**
 * Isolated target register-number descriptions. Values mirror the named
 * Ghidra 12.0.3 {@code *.dwarf} mapping resource, using the canonical ARM
 * double-register subset required by AADWARF32; generic storage code never
 * infers a DWARF number from a register name or ordinal.
 */
public record TargetRegisterMap(String target, String provenance,
        Map<String, Integer> dwarfNumbers, Map<String, List<PairPiece>> registerPairs) {
    private static final String GHIDRA_MAPPING_ROOT =
        "Ghidra 12.0.3 processor DWARF register mapping: ";

    /** Expected physical child position; list order describes object memory. */
    public record PairPiece(String registerName, int baseBitOffset, int bitSize) {
        public PairPiece {
            if (registerName == null || registerName.isBlank() ||
                    baseBitOffset < 0 || bitSize <= 0) {
                throw new IllegalArgumentException("invalid paired-register piece");
            }
        }
    }

    public TargetRegisterMap(String target, String provenance, Map<String, Integer> dwarfNumbers) {
        this(target, provenance, dwarfNumbers, Map.of());
    }

    public TargetRegisterMap {
        if (target == null || target.isBlank() || provenance == null ||
                provenance.isBlank() || dwarfNumbers == null || dwarfNumbers.isEmpty() || registerPairs == null) {
            throw new IllegalArgumentException("invalid target register map");
        }
        Map<String, Integer> sorted = new TreeMap<>();
        for (Map.Entry<String, Integer> entry : dwarfNumbers.entrySet()) {
            if (entry.getKey() == null || entry.getKey().isBlank() ||
                    entry.getValue() == null || entry.getValue() < 0 ||
                    sorted.put(entry.getKey(), entry.getValue()) != null) {
                throw new IllegalArgumentException("invalid or duplicate register mapping");
            }
        }
        dwarfNumbers = Collections.unmodifiableMap(new LinkedHashMap<>(sorted));
        Map<String, List<PairPiece>> pairs = new TreeMap<>();
        for (var entry : registerPairs.entrySet()) {
            if (entry.getKey() == null || entry.getKey().isBlank() || entry.getValue() == null ||
                    entry.getValue().size() != 2) {
                throw new IllegalArgumentException("invalid paired-register description");
            }
            var pieces = List.copyOf(entry.getValue());
            if (pieces.get(0).registerName().equals(pieces.get(1).registerName()) ||
                    pieces.stream().anyMatch(piece -> !sorted.containsKey(piece.registerName()))) {
                throw new IllegalArgumentException("unmapped or duplicate paired-register child");
            }
            PairPiece low = pieces.get(0).baseBitOffset() < pieces.get(1).baseBitOffset()
                ? pieces.get(0) : pieces.get(1);
            PairPiece high = low == pieces.get(0) ? pieces.get(1) : pieces.get(0);
            if (low.baseBitOffset() != 0 || high.baseBitOffset() != low.bitSize()) {
                throw new IllegalArgumentException("paired-register pieces overlap or have a gap");
            }
            pairs.put(entry.getKey(), pieces);
        }
        registerPairs = Collections.unmodifiableMap(pairs);
    }

    /** Additional pair semantics require explicit original-ELF ABI evidence. */
    public static TargetRegisterMap forElf(String target, ElfImage elf, BooleanSupplier cancelled)
            throws IOException {
        TargetRegisterMap ordinary = forTarget(target);
        if (!target.equals("mips") && !target.equals("mipsel")) {
            return ordinary;
        }
        boolean bigEndian = elf.byteOrder() == ByteOrder.BIG_ENDIAN;
        if (!target.equals(bigEndian ? "mips" : "mipsel") ||
                !MipsAbiFlags.observe(elf, cancelled).fp32PairContract()) {
            return ordinary;
        }
        Map<String, List<PairPiece>> pairs = new LinkedHashMap<>();
        for (int first = 0; first < 32; first += 2) {
            PairPiece low = new PairPiece("f" + first, 0, 32);
            PairPiece high = new PairPiece("f" + (first + 1), 32, 32);
            pairs.put("f" + first + "_" + (first + 1),
                bigEndian ? List.of(high, low) : List.of(low, high));
        }
        return new TargetRegisterMap(target, ordinary.provenance() +
            "; explicit ELF32 O32 MIPS32r2 FP32 ABI record; paired FPR children", ordinary.dwarfNumbers(), pairs);
    }

    public static TargetRegisterMap forTarget(String target) {
        return switch (target) {
            case "x86_64" -> x86_64();
            case "aarch64" -> aarch64();
            case "arm", "arm32" -> arm32();
            case "mips", "mipsel" -> mips(target);
            default -> throw new IllegalArgumentException(
                "no audited DWARF register map for target " + target);
        };
    }

    public Storage register(String ghidraName, int valueBitOffset, int bitSize) {
        Integer dwarfNumber = dwarfNumbers.get(ghidraName);
        if (dwarfNumber == null) {
            return unavailable(ghidraName);
        }
        return new RegisterStorage(new DwarfRegister(ghidraName, dwarfNumber),
            valueBitOffset, bitSize);
    }

    public Storage registerRelative(String ghidraName, long byteOffset) {
        Integer dwarfNumber = dwarfNumbers.get(ghidraName);
        if (dwarfNumber == null) {
            return unavailable(ghidraName);
        }
        return new RegisterRelativeStorage(
            new DwarfRegister(ghidraName, dwarfNumber), byteOffset);
    }

    private UnavailableStorage unavailable(String ghidraName) {
        String display = ghidraName == null ? "<null>" : ghidraName;
        return new UnavailableStorage(OmissionReason.UNMAPPED_REGISTER,
            "target " + target + " has no audited DWARF mapping for Ghidra register " +
                display);
    }

    private static TargetRegisterMap x86_64() {
        Map<String, Integer> result = new LinkedHashMap<>();
        put(result, 0, "RAX");
        put(result, 1, "RDX");
        put(result, 2, "RCX");
        put(result, 3, "RBX");
        put(result, 4, "RSI");
        put(result, 5, "RDI");
        put(result, 6, "RBP");
        put(result, 7, "RSP");
        putRange(result, 8, 8, "R");
        put(result, 16, "RIP");
        putRange(result, 17, 16, "XMM", 0);
        putRange(result, 33, 8, "ST", 0);
        putRange(result, 41, 8, "MM", 0);
        put(result, 49, "rflags");
        put(result, 50, "ES");
        put(result, 51, "CS");
        put(result, 52, "SS");
        put(result, 53, "DS");
        put(result, 54, "FS");
        put(result, 55, "GS");
        put(result, 62, "TR");
        put(result, 63, "LDTR");
        put(result, 64, "MXCSR");
        return new TargetRegisterMap("x86_64",
            GHIDRA_MAPPING_ROOT + "Processors/x86/data/languages/x86-64.dwarf", result);
    }

    private static TargetRegisterMap aarch64() {
        Map<String, Integer> result = new LinkedHashMap<>();
        putRange(result, 0, 31, "x", 0);
        put(result, 31, "sp");
        putRange(result, 64, 32, "q", 0);
        return new TargetRegisterMap("aarch64",
            GHIDRA_MAPPING_ROOT + "Processors/AARCH64/data/languages/AARCH64.dwarf",
            result);
    }

    private static TargetRegisterMap arm32() {
        Map<String, Integer> result = new LinkedHashMap<>();
        putRange(result, 0, 13, "r", 0);
        put(result, 13, "sp");
        put(result, 14, "lr");
        put(result, 15, "pc");
        put(result, 16, "fpsr");
        put(result, 17, "cpsr");
        // Arm's DWARF ABI describes scalar single-precision slices through
        // canonical double-precision registers; 64..95 are legacy numbering.
        putRange(result, 256, 32, "d", 0);
        return new TargetRegisterMap("arm",
            GHIDRA_MAPPING_ROOT + "Processors/ARM/data/languages/ARMneon.dwarf; " +
                "canonical D-register subset: ARM AADWARF32 2025Q4",
            result);
    }

    private static TargetRegisterMap mips(String target) {
        Map<String, Integer> result = new LinkedHashMap<>();
        String[] lowRegisters = { "zero", "at", "v0", "v1" };
        for (int index = 0; index < lowRegisters.length; index++) {
            put(result, index, lowRegisters[index]);
        }
        putRange(result, 4, 4, "a", 0);
        putRange(result, 8, 8, "t", 0);
        putRange(result, 16, 8, "s", 0);
        put(result, 24, "t8");
        put(result, 25, "t9");
        put(result, 26, "k0");
        put(result, 27, "k1");
        put(result, 28, "gp");
        put(result, 29, "sp");
        put(result, 30, "s8");
        put(result, 31, "ra");
        putRange(result, 32, 32, "f", 0);
        return new TargetRegisterMap(target,
            GHIDRA_MAPPING_ROOT + "Processors/MIPS/data/languages/mips.dwarf", result);
    }

    private static void putRange(Map<String, Integer> result, int dwarfStart,
            int count, String prefix) {
        putRange(result, dwarfStart, count, prefix, dwarfStart);
    }

    private static void putRange(Map<String, Integer> result, int dwarfStart,
            int count, String prefix, int nameStart) {
        for (int index = 0; index < count; index++) {
            put(result, dwarfStart + index, prefix + (nameStart + index));
        }
    }

    private static void put(Map<String, Integer> result, int dwarfNumber,
            String ghidraName) {
        if (result.put(ghidraName, dwarfNumber) != null) {
            throw new IllegalStateException("duplicate register " + ghidraName);
        }
    }
}
