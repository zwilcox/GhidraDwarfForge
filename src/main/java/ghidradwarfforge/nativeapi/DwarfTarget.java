package ghidradwarfforge.nativeapi;

import static ghidradwarfforge.nativeapi.DwarfConstants.DW_DLC_OFFSET32;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_DLC_POINTER32;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_DLC_POINTER64;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_DLC_SYMBOLIC_RELOCATIONS;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_DLC_TARGET_BIGENDIAN;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_DLC_TARGET_LITTLEENDIAN;

import java.io.IOException;
import java.nio.ByteOrder;
import java.util.List;
import java.util.Map;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

import ghidradwarfforge.elf.Arm32ModeSymbols;
import ghidradwarfforge.elf.Arm32FunctionAliasSymbols;
import ghidradwarfforge.elf.ElfFunctionModeCue;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.elf.ElfLocalFunctionSymbol;
import ghidradwarfforge.elf.ElfFunctionAlias;
import ghidradwarfforge.elf.FunctionAliasSymbols;
import ghidradwarfforge.elf.MipsFunctionAliasSymbols;
import ghidradwarfforge.elf.MipsFloatingCallPolicy;
import ghidradwarfforge.elf.MipsAggregateCallPolicy;
import ghidradwarfforge.elf.MipsWideCallPolicy;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.DebuggerCallRestrictions;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;

/** Table-driven libdwarf target description derived from the original ELF. */
public record DwarfTarget(String name, String producerIsa, int addressBytes,
        boolean littleEndian, String ghidraProcessor) {
    private static final int EM_386 = 3;
    private static final int EM_MIPS = 8;
    private static final int EM_ARM = 40;
    private static final int EM_X86_64 = 62;
    private static final int EM_AARCH64 = 183;
    // Ghidra 12.0.3 compiler specifications used by the ELF runtime baselines.
    // Membership preserves the existing policy; it does not certify every
    // signature, language variant or ABI flag combination for injected calls.
    private static final Map<String, String> BASELINE_COMPILER_SPECS = Map.of(
        "x86", "gcc", "x86_64", "gcc", "aarch64", "default",
        "arm", "default", "mips", "default", "mipsel", "default");
    // Processor identities follow Ghidra 12.0.3's ELF .opinion and .ldefs files.
    // Language variants and compiler-spec IDs are not portable ABI identifiers.
    private static final Map<Integer, List<TargetDescription>> TARGETS = Map.of(
        EM_386, List.of(new TargetDescription("i386", 4, "x86", null, "x86", false, "x86")),
        EM_MIPS, List.of(
            new TargetDescription("MIPS32", 4, "mipsel", "mips", "mips", true, "MIPS"),
            new TargetDescription("MIPS64", 8, "mips64el", "mips64", "mips", true, "MIPS")),
        EM_ARM, List.of(new TargetDescription("ARM", 4, "arm", "arm", "arm", true, "ARM")),
        EM_X86_64, List.of(
            new TargetDescription("x86-64", 8, "x86_64", null, "x86_64", false, "x86")),
        EM_AARCH64, List.of(
            new TargetDescription("AArch64", 8, "aarch64", null, "arm64", false, "AARCH64")));

    private record TargetDescription(String displayName, int addressBytes,
            String littleEndianName, String bigEndianName, String producerIsa,
            boolean bigEndianSupported, String ghidraProcessor) {

        private DwarfTarget create(int actualAddressBytes, ByteOrder byteOrder) {
            if (actualAddressBytes != addressBytes) {
                throw new IllegalArgumentException(displayName + " requires ELF" +
                    (addressBytes * 8) + ", found ELF" + (actualAddressBytes * 8));
            }
            boolean littleEndian = byteOrder == ByteOrder.LITTLE_ENDIAN;
            if (!littleEndian && !bigEndianSupported) {
                throw new IllegalArgumentException(displayName +
                    " big-endian producer mode has not been audited");
            }
            String targetName = littleEndian ? littleEndianName : bigEndianName;
            if (targetName == null) {
                throw new IllegalArgumentException(displayName +
                    " byte order has no audited target description");
            }
            return new DwarfTarget(targetName, producerIsa, addressBytes, littleEndian,
                ghidraProcessor);
        }
    }

    public DwarfTarget {
        if (name == null || name.isBlank() || producerIsa == null ||
                producerIsa.isBlank() || (addressBytes != 4 && addressBytes != 8) ||
                ghidraProcessor == null || ghidraProcessor.isBlank()) {
            throw new IllegalArgumentException("invalid DWARF target description");
        }
    }

    public static DwarfTarget fromElf(ElfImage elf) {
        Arm32EndianProfile.requireSupportedEncoding(elf);
        int addressBytes = elf.is64Bit() ? 8 : 4;
        return fromMetadata(elf.machine(), addressBytes, elf.byteOrder());
    }

    /** A mixed-endian ELF can constrain instructions independently of data. */
    public ByteOrder requiredInstructionByteOrder(ElfImage elf) {
        if (!equals(fromElf(elf))) throw new IllegalArgumentException("instruction target disagrees with ELF");
        return Arm32EndianProfile.instructionByteOrder(elf);
    }

    static DwarfTarget fromMetadata(int machine, int addressBytes, ByteOrder byteOrder) {
        if (byteOrder == null) {
            throw new IllegalArgumentException("ELF byte order is required");
        }
        List<TargetDescription> descriptions = TARGETS.get(machine);
        if (descriptions == null) {
            throw new IllegalArgumentException("unsupported ELF machine " + machine +
                "; add an audited libdwarf target description before exporting");
        }
        TargetDescription description = descriptions.stream()
            .filter(candidate -> candidate.addressBytes() == addressBytes)
            .findFirst().orElse(descriptions.getFirst());
        return description.create(addressBytes, byteOrder);
    }

    public long producerFlags() {
        long pointerFlag = addressBytes == 8 ? DW_DLC_POINTER64 : DW_DLC_POINTER32;
        long byteOrderFlag = littleEndian
                ? DW_DLC_TARGET_LITTLEENDIAN : DW_DLC_TARGET_BIGENDIAN;
        return pointerFlag | DW_DLC_OFFSET32 | DW_DLC_SYMBOLIC_RELOCATIONS |
            byteOrderFlag;
    }

    /** A program-default name is not proof of the original ELF consumer's ABI. */
    public String compilerSpecCallRestriction(String languageId, String compilerSpecId) {
        String baseline = BASELINE_COMPILER_SPECS.get(name);
        if (baseline != null && baseline.equals(compilerSpecId)) {
            // AppleSilicon/default is a different ABI despite sharing the
            // processor, pointer width, byte order and compiler ID with v8A.
            if (name.equals("aarch64") && !"AARCH64:LE:64:v8A".equals(languageId)) {
                return "selected Ghidra language " + languageId + " with compiler " + compilerSpecId +
                    " has no validated default debugger ABI mapping for ELF target " + name;
            }
            return "";
        }
        return "selected Ghidra compiler specification " + compilerSpecId +
            " has no validated default debugger ABI mapping for ELF target " + name;
    }

    /** Metadata compatibility is not a claim that all instructions or signatures are supported. */
    public String elfAbiCallRestriction(ElfImage image) {
        if (!equals(fromElf(image))) throw new IllegalArgumentException("call ABI target disagrees with ELF");
        if (Arm32EndianProfile.isBe8(image)) {
            return "ARM BE8 debugger call ABI has not been validated for recovered signatures";
        }
        if (!name.equals("aarch64")) return "";
        byte[] header = image.headerBytes();
        int osAbi = Byte.toUnsignedInt(header[7]);
        int abiVersion = Byte.toUnsignedInt(header[8]);
        // AAELF64 2025Q4: processor flags are reserved and must be zero.
        // OSABI=0 denotes generic ELF, not proof of a particular operating system.
        // The tested consumer is Linux/System V; other platform/version choices
        // retain their metadata and recovered knowledge but do not establish calls.
        if ((image.type() != 2 && image.type() != 3) || image.flags() != 0 ||
                (osAbi != 0 && osAbi != 3) || abiVersion != 0) {
            return "AArch64 ELF metadata has no validated LP64 debugger call profile: type=" +
                image.type() + ", flags=0x" + Long.toHexString(image.flags()) +
                ", OSABI=" + osAbi + ", ABI-version=" + abiVersion;
        }
        return "";
    }

    /** Target ABI guards preserve the signature while preventing unverified debugger calls. */
    public ProgramTypeModel applyCallRestrictions(ElfImage image, ProgramTypeModel model,
            BooleanSupplier cancelled, Consumer<String> diagnostic) throws IOException {
        if (!equals(fromElf(image))) {
            throw new IllegalArgumentException("call ABI target disagrees with ELF");
        }
        if (MipsWideCallPolicy.isWideCandidate(image)) {
            return MipsWideCallPolicy.apply(image, model, cancelled, diagnostic);
        }
        return DebuggerCallRestrictions.applyAll(MipsAggregateCallPolicy.apply(image,
            MipsFloatingCallPolicy.apply(image, model, cancelled, diagnostic), cancelled, diagnostic),
            elfAbiCallRestriction(image), cancelled, diagnostic);
    }

    /** Direct code-address values only; tagged/descriptor ABIs need their own binding proof. */
    public List<ElfLocalFunctionSymbol> planFunctionAliases(ElfImage image,
            List<ElfFunctionAlias> aliases, List<FunctionSymbol> functions,
            List<ElfLocalFunctionSymbol> reserved, BooleanSupplier cancelled,
            Consumer<String> diagnostic) throws IOException {
        return planFunctionAliases(image, aliases, functions, reserved, List.of(), cancelled, diagnostic);
    }

    public List<ElfLocalFunctionSymbol> planFunctionAliases(ElfImage image,
            List<ElfFunctionAlias> aliases, List<FunctionSymbol> functions,
            List<ElfLocalFunctionSymbol> reserved, List<ElfFunctionModeCue> aliasModeCues,
            BooleanSupplier cancelled, Consumer<String> diagnostic) throws IOException {
        if (aliases.isEmpty()) {
            return List.of();
        }
        if (!equals(fromElf(image))) {
            throw new IllegalArgumentException("function-alias target disagrees with ELF");
        }
        if (image.machine() == EM_MIPS) {
            return MipsFunctionAliasSymbols.plan(image, aliases, functions, reserved, cancelled, diagnostic);
        }
        if (image.machine() == EM_ARM) {
            return Arm32FunctionAliasSymbols.plan(image, aliases, functions, reserved,
                aliasModeCues, cancelled, diagnostic);
        }
        if (!List.of("x86", "x86_64", "aarch64").contains(name)) {
            diagnostic.accept("Omitted function aliases: target " + name +
                " has no audited alias symbol-value policy");
            return List.of();
        }
        return FunctionAliasSymbols.plan(image, aliases, functions, reserved, cancelled, diagnostic);
    }

    /** Target-specific ELF symbol semantics stay outside generic DWARF/address handling. */
    public List<ElfLocalFunctionSymbol> planFunctionModeSymbols(ElfImage image,
            List<ElfFunctionModeCue> cues, List<FunctionSymbol> functions, BooleanSupplier cancelled,
            Consumer<String> diagnostic) throws IOException {
        if (cues.isEmpty()) {
            return List.of();
        }
        if (!equals(fromElf(image))) {
            throw new IllegalArgumentException("function-mode target disagrees with ELF");
        }
        if (image.machine() == EM_ARM) {
            if (image.type() == 3 || image.sections().isEmpty()) {
                return Arm32ModeSymbols.planRecovered(image, cues, functions, cancelled, diagnostic);
            }
            return Arm32ModeSymbols.plan(image, cues, cancelled, diagnostic);
        }
        diagnostic.accept("Omitted function-mode symbols: target " + name +
            " has no audited mode-symbol planner");
        return List.of();
    }

}
