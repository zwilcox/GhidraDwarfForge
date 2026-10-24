package ghidradwarfforge;

import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.nativeapi.DwarfTarget;

/** Rejects definite target contradictions before extracting a Program's knowledge. */
public final class GhidraTargetAgreement {
    private GhidraTargetAgreement() {
    }

    /**
     * Pointer width is the Program's data pointer width, not its register or
     * instruction width. Language variants and compiler specifications are
     * reported but not used to infer an ABI or overwrite analyst choices.
     */
    public static DwarfTarget requireAgreement(Program program, ElfImage elf) {
        DwarfTarget target = DwarfTarget.fromElf(elf);
        Language language = program.getLanguage();
        String processor = language.getProcessor().toString();
        int pointerBytes = program.getDefaultPointerSize();
        boolean littleEndian = !language.isBigEndian();
        if (!target.ghidraProcessor().equals(processor) ||
                target.addressBytes() != pointerBytes ||
                target.littleEndian() != littleEndian) {
            throw new IllegalStateException("ELF/Ghidra target mismatch: ELF machine=" +
                elf.machine() + ", class=ELF" + (target.addressBytes() * 8) +
                ", byte-order=" + byteOrder(target.littleEndian()) +
                ", flags=0x" + Long.toHexString(elf.flags()) +
                ", expected-processor=" + target.ghidraProcessor() +
                "; Ghidra processor=" + processor +
                ", pointer-bits=" + (pointerBytes * 8) +
                ", byte-order=" + byteOrder(littleEndian) +
                ", language=" + language.getLanguageID() +
                ", compiler=" + program.getCompilerSpec().getCompilerSpecID() +
                "; export stopped before extraction and native production");
        }
        return target;
    }

    private static String byteOrder(boolean littleEndian) {
        return littleEndian ? "little" : "big";
    }
}
