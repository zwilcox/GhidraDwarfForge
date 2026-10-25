package ghidradwarfforge.elf;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/** Bounded MIPS ABI-record observation; header flags alone do not identify FP mode. */
public final class MipsAbiFlags {
    private static final long SECTION_TYPE = 0x7000002aL;
    private static final long SEGMENT_TYPE = 0x70000003L;
    private static final int RECORD_BYTES = 24;

    public enum Status { NOT_MIPS, ABSENT, AVAILABLE, UNSUPPORTED, AMBIGUOUS }

    public record Fields(int version, int isaLevel, int isaRevision, int gprSize,
            int cpr1Size, int cpr2Size, int fpAbi, long isaExtension, long ases,
            long flags1, long flags2) {
    }

    public record Observation(Status status, Optional<Fields> fields,
            boolean fp32PairContract, String detail) {
        public Observation {
            if (status == null || fields == null || detail == null ||
                    (status == Status.AVAILABLE) != fields.isPresent() ||
                    (fp32PairContract && status != Status.AVAILABLE)) {
                throw new IllegalArgumentException("inconsistent MIPS ABI observation");
            }
        }
    }

    /** First audited envelope: ELF32 O32 MIPS32r2 with explicit 32-bit FPRs. */
    private static boolean hasFp32PairContract(ElfImage elf, Fields f) {
        if (elf.machine() != 8 || elf.is64Bit() ||
                (elf.type() != 2 && elf.type() != 3)) {
            return false;
        }
        // Admit only the observed O32/r2 profile plus the three ordinary
        // NOREORDER/PIC/CPIC bits. ABI2, FP64 and unknown flag combinations
        // never silently select a paired-register interpretation.
        return (elf.flags() & ~7L) == 0x70001000L &&
            f.version() == 0 && f.isaLevel() == 32 && f.isaRevision() == 2 &&
            f.gprSize() == 1 && f.cpr1Size() == 1 && f.cpr2Size() == 0 &&
            f.fpAbi() == 1 && f.isaExtension() == 0 && f.ases() == 0 &&
            (f.flags1() & ~1L) == 0 && f.flags2() == 0;
    }

    private record View(long offset, long size) {
    }

    private MipsAbiFlags() {
    }

    public static Observation observe(ElfImage elf, BooleanSupplier cancelled) throws IOException {
        checkCancelled(cancelled);
        if (elf.machine() != 8) {
            return result(Status.NOT_MIPS, "ELF machine is not MIPS");
        }
        List<View> sections = new ArrayList<>();
        List<View> segments = new ArrayList<>();
        for (ElfImage.Section section : elf.sections()) {
            checkCancelled(cancelled);
            if (section.type == SECTION_TYPE) {
                if ((section.flags & 0x800L) != 0) {
                    return result(Status.UNSUPPORTED, "compressed MIPS ABI record is not decoded");
                }
                sections.add(new View(section.offset, section.size));
            }
        }
        for (ElfImage.Segment segment : elf.segments()) {
            checkCancelled(cancelled);
            if (segment.type == SEGMENT_TYPE) {
                if (segment.fileSize != segment.memorySize) {
                    return result(Status.UNSUPPORTED, "ABI segment file/memory sizes differ");
                }
                segments.add(new View(segment.offset, segment.fileSize));
            }
        }
        if (sections.size() > 1 || segments.size() > 1) {
            return result(Status.AMBIGUOUS, "multiple MIPS ABI sections or segments");
        }
        if (sections.isEmpty() && segments.isEmpty()) {
            return result(Status.ABSENT, "no typed MIPS ABI record");
        }
        if (!sections.isEmpty() && !segments.isEmpty() &&
                !sections.getFirst().equals(segments.getFirst())) {
            return result(Status.AMBIGUOUS, "section and segment identify different ABI bytes");
        }
        View view = sections.isEmpty() ? segments.getFirst() : sections.getFirst();
        if (view.size() != RECORD_BYTES) {
            return result(Status.UNSUPPORTED, "MIPS ABI record is not exactly 24 bytes");
        }
        checkCancelled(cancelled);
        ByteBuffer bytes = ByteBuffer.wrap(elf.readSourceRange(view.offset(), view.size(),
            "MIPS ABI flags")).order(elf.byteOrder());
        Fields fields = new Fields(Short.toUnsignedInt(bytes.getShort()),
            Byte.toUnsignedInt(bytes.get()), Byte.toUnsignedInt(bytes.get()),
            Byte.toUnsignedInt(bytes.get()), Byte.toUnsignedInt(bytes.get()),
            Byte.toUnsignedInt(bytes.get()), Byte.toUnsignedInt(bytes.get()),
            Integer.toUnsignedLong(bytes.getInt()), Integer.toUnsignedLong(bytes.getInt()),
            Integer.toUnsignedLong(bytes.getInt()), Integer.toUnsignedLong(bytes.getInt()));
        checkCancelled(cancelled);
        if (fields.version() != 0) {
            return result(Status.UNSUPPORTED, "MIPS ABI record version is not zero");
        }
        return new Observation(Status.AVAILABLE, Optional.of(fields), hasFp32PairContract(elf, fields),
            sections.isEmpty() ? "program-header ABI record" :
                segments.isEmpty() ? "section-header ABI record" : "matching section/program ABI record");
    }

    private static Observation result(Status status, String detail) {
        return new Observation(status, Optional.empty(), false, detail);
    }

    private static void checkCancelled(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) {
            throw new CancellationException("MIPS ABI observation cancelled");
        }
    }
}
