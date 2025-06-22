// GhidraDwarfForgeFixed.java
// Minimal DWARF side-car generator with correctly attributed DIEs and diagnostics
// Requires LibDwarfp.java (your JNA mapping) to be present in the same package.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import java.nio.charset.StandardCharsets;

import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.NativeLongByReference;
import com.sun.jna.ptr.PointerByReference;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

/**
 * Generates a “<binary>.dbg” ELF 64 REL file containing a minimal set of
 * DWARF 5 sections (.debug_info / .debug_abbrev / .debug_aranges).
 *
 * NOTE: libdwarfp (producer mode) must export the functions mapped in
 * LibDwarfp.
 */
public class GhidraDwarfForgeFixed extends GhidraScript {

    /* ------------------------------------------------------------------ */
    /* simple POD helpers */
    /* ------------------------------------------------------------------ */

    private static final class Range {
        final long start, length;

        Range(long s, long l) {
            start = s;
            length = l;
        }
    }

    private static final class SectionData {
        String name;
        byte[] contents;
    }

    private static final class SectionCollector {
        final Map<String, SectionData> sections = new LinkedHashMap<>();
    }

    /* global per-run collector (needed by the header callback) */
    private final SectionCollector collector = new SectionCollector();

    /* ------------------------------------------------------------------ */
    /* JNA callback wrappers */
    /* ------------------------------------------------------------------ */

    class SectionHeaderCallback implements LibDwarfp.DwarfCallbackFunc {

        private int nextIdx = 1;

        @Override
        public int apply(Pointer name, int size,
                NativeLong type, NativeLong flags,
                NativeLong link, NativeLong info,
                NativeLongByReference sectIdxOut,
                Pointer userData,
                IntByReference errOut) {

            String secName = name.getString(0);
            println("Generated DWARF section: " + secName);

            SectionData sd = new SectionData();
            sd.name = secName;
            collector.sections.put(secName, sd);

            sectIdxOut.setValue(new NativeLong(nextIdx));
            errOut.setValue(0);
            return nextIdx++;
        }
    }

    private static final class ErrorCallback implements LibDwarfp.Dwarf_Error_Handler {
        @Override
        public void invoke(int errno, Pointer arg) {
            System.err.println("libdwarf error " + errno);
        }
    }

    /* ------------------------------------------------------------------ */
    /* entry-point */
    /* ------------------------------------------------------------------ */

    @Override
    protected void run() throws Exception {

        println("initializing…");

        if (currentProgram == null) {
            printerr("No program loaded - open a binary in Ghidra first, then run the script.");
            return;
        }

        int ptrSize = currentProgram.getDefaultPointerSize();
        Endian endian = currentProgram.getLanguage().getLanguageDescription().getEndian();
        String abi = getAbi(currentProgram);

        println("Pointer size  : " + ptrSize + "-byte");
        println("Endianness    : " + (endian == Endian.BIG ? "big" : "little"));
        println("ISA/ABI       : " + abi);

        int dlcFlags = (ptrSize > 4 ? DwarfConst.DW_DLC_POINTER64 | DwarfConst.DW_DLC_OFFSET64
                : DwarfConst.DW_DLC_POINTER32 | DwarfConst.DW_DLC_OFFSET32)
                | (endian == Endian.BIG ? DwarfConst.DW_DLC_TARGET_BIGENDIAN
                        : DwarfConst.DW_DLC_TARGET_LITTLEENDIAN)
                | DwarfConst.DW_DLC_SYMBOLIC_RELOCATIONS;

        println(String.format("libdwarf dlc flags: 0x%08x", dlcFlags));

        List<Range> ranges = collectExecutableRanges();
        println("Executable ranges: " + ranges.size());

        produceDwarf(ranges, dlcFlags, abi);
        println("Emitted DWARF sections: " + collector.sections.keySet());

        emitElf(collector.sections,
                endian,
                ptrSize > 4);
        println("\nWrote side-car ELF ⇒ " + currentProgram.getExecutablePath() + ".dbg");
    }

    /* ------------------------------------------------------------------ */
    /* DWARF generation */
    /* ------------------------------------------------------------------ */

    private void produceDwarf(List<Range> ranges, int dlcFlags, String abi) throws IOException {

        var dbgRef = new PointerByReference();
        var errRef = new PointerByReference();

        int ok = LibDwarfp.INSTANCE.dwarf_producer_init(
                DwarfConst.DW_DLC_WRITE | dlcFlags,
                new SectionHeaderCallback(),
                new ErrorCallback(),
                null,
                null,
                abi,
                "V5",
                null,
                dbgRef, errRef);

        if (ok != DwarfConst.DW_DLV_OK)
            throw new IOException("dwarf_producer_init failed (" + ok + ")");

        var dbg = new LibDwarfp.Dwarf_P_Debug(dbgRef.getValue());
        var attr = new PointerByReference();

        /* --- CU DIE -------------------------------------------------- */
        var cuRef = new PointerByReference();
        LibDwarfp.INSTANCE.dwarf_new_die_a(
                dbg,
                new NativeLong(DwarfConst.DW_TAG_compile_unit),
                null,
                null,
                null,
                null,
                cuRef,
                errRef);

        var cuDie = new LibDwarfp.Dwarf_P_Die(cuRef.getValue());

        LibDwarfp.INSTANCE.dwarf_add_die_to_debug_a(dbg, cuDie, errRef);
        LibDwarfp.INSTANCE.dwarf_add_AT_name_a(cuDie, currentProgram.getName(), attr, errRef);
        LibDwarfp.INSTANCE.dwarf_add_AT_producer_a(cuDie, "GhidraDwarfForge", attr, errRef);

        long lo = ranges.get(0).start;
        long hi = ranges.stream().mapToLong(r -> r.start + r.length).max().orElse(lo);

        LibDwarfp.INSTANCE.dwarf_add_AT_targ_address_c(
                dbg,
                cuDie,
                (short) DwarfConst.DW_AT_low_pc,
                DwarfConst.DW_DLV_NOCOUNT,
                lo, /* offset / value */
                errRef);

        LibDwarfp.INSTANCE.dwarf_add_AT_unsigned_const_a(
                dbg,
                cuDie,
                (short) DwarfConst.DW_AT_high_pc,
                hi - lo,
                attr,
                errRef);

        LibDwarfp.INSTANCE.dwarf_add_AT_unsigned_const_a(
                dbg,
                cuDie,
                (short) DwarfConst.DW_AT_language,
                0x0001,
                attr,
                errRef);

        /* --- address ranges ----------------------------------------- */
        for (Range r : ranges)
            LibDwarfp.INSTANCE.dwarf_add_arange_c(dbg,
                    r.start,
                    r.length,
                    0,
                    0,
                    0,
                    errRef);

        LibDwarfp.INSTANCE.dwarf_transform_to_disk_form_a(dbg, errRef);

        /* collect three core sections */
        record Sect(String name, int kind) {
        }
        List<Sect> wanted = List.of(
                new Sect(".debug_info", DwarfConst.DW_SECT_INFO),
                new Sect(".debug_abbrev", DwarfConst.DW_SECT_ABBREV),
                new Sect(".debug_aranges", DwarfConst.DW_SECT_ARANGES));

        for (Sect s : wanted) {
            NativeLongByReference elfIdx = new NativeLongByReference();
            NativeLongByReference lenOut = new NativeLongByReference();
            PointerByReference bufOut = new PointerByReference();

            int res = LibDwarfp.INSTANCE.dwarf_get_section_bytes_a(
                    dbg, s.kind(), elfIdx, lenOut, bufOut, errRef);

            if (res != DwarfConst.DW_DLV_OK) {
                println("⚠  libdwarf did not return " + s.name());
                continue;
            }

            Pointer p = bufOut.getValue();
            long n = lenOut.getValue().longValue();

            if (p == null || n == 0) {
                println("⚠  Section " + s.name() + " came back empty");
                continue;
            }
            if (n > Integer.MAX_VALUE)
                throw new IOException("Section " + s.name() + " > 2 GiB");

            SectionData sd = new SectionData();
            sd.name = s.name();
            sd.contents = p.getByteArray(0, (int) n);
            collector.sections.put(sd.name, sd);

            println("  • collected " + s.name() + " (" + n + " bytes)");
        }

        record RelSect(String name, int kind) {
        }
        List<RelSect> relWanted = List.of(
                new RelSect(".rel.debug_info", DwarfConst.DW_SECT_REL_INFO),
                new RelSect(".rel.debug_aranges", DwarfConst.DW_SECT_REL_ARANGES),
                new RelSect(".rela.debug_info", DwarfConst.DW_SECT_RELA_INFO),
                new RelSect(".rela.debug_aranges", DwarfConst.DW_SECT_RELA_ARANGES));

        for (RelSect s : relWanted) {
            NativeLongByReference elfIdx = new NativeLongByReference();
            NativeLongByReference lenOut = new NativeLongByReference();
            PointerByReference bufOut = new PointerByReference();

            int res = LibDwarfp.INSTANCE.dwarf_get_section_bytes_a(
                    dbg, s.kind(), elfIdx, lenOut, bufOut, errRef);

            if (res != DwarfConst.DW_DLV_OK) // producer did not create it
                continue;

            long n = lenOut.getValue().longValue();
            if (n == 0)
                continue;

            SectionData sd = new SectionData();
            sd.name = s.name();
            sd.contents = bufOut.getValue().getByteArray(0, (int) n);
            collector.sections.put(sd.name, sd);

            println("  • collected " + s.name() + " (" + n + " bytes)");
        }

        LibDwarfp.INSTANCE.dwarf_producer_finish_a(dbg, errRef);
    }

    /**
     * Write a minimal 64‑bit ELF REL file that contains only the
     * DWARF sections whose byte‑payloads are present in {@code secs}.
     */
    private static short elfMachine(String proc) {
        return switch (proc) {
            case "x86" -> (short) 0x3e; // EM_X86_64 (we emit 64‑bit only)
            case "ARM" -> (short) 0x28; // EM_ARM
            case "AArch64" -> (short) 0xb7; // EM_AARCH64
            case "PowerPC" -> (short) 0x15; // EM_PPC64
            case "MIPS" -> (short) 0x08; // EM_MIPS (assumes 64‑bit ABI)
            default -> (short) 0; // Unknown → EM_NONE
        };
    }

    /** Architecture‑specific flags that must go into e_flags */
    private static int elfFlags(short eMachine) {
        return switch (eMachine) {
            case 0x28 -> 0x05000000; // EF_ARM_EABI_VER5 – the usual for modern ARM EABI
            case 0xb7 -> 0; // AArch64 does not define flags for relocatable OBJs
            default -> 0; // x86‑64, MIPS, PPC64 … leave 0
        };
    }

    /* ------------------------------------------------------------------ */
    /* Emit a minimal 64‑bit relocatable ELF with DWARF (+ reloc) */
    /* ------------------------------------------------------------------ */
    private void emitElf(Map<String, SectionData> secs, Endian endian, boolean is64) throws IOException {

        final int EH_SIZE = 64; // ELF header size
        final int SH_SIZE = 64; // section‑header size
        final boolean bigEndian = (endian == Endian.BIG);

        /* -------- Split sections into ‘regular’ vs ‘relocation’ ------------- */
        List<SectionData> regular = new ArrayList<>();
        List<SectionData> reloc = new ArrayList<>();

        for (SectionData s : secs.values()) {
            if (s.contents == null || s.contents.length == 0)
                continue; // ignore empty placeholders
            (s.name.startsWith(".rel") || s.name.startsWith(".rela") ? reloc : regular).add(s);
        }

        /* -------- Build .shstrtab ------------------------------------------- */
        ByteArrayOutputStream shstr = new ByteArrayOutputStream();
        shstr.write(0); // index 0 = empty string
        Map<String, Integer> strOff = new LinkedHashMap<>();
        for (SectionData s : regular) {
            strOff.put(s.name, shstr.size());
            shstr.write(s.name.getBytes(StandardCharsets.US_ASCII));
            shstr.write(0);
        }
        for (SectionData s : reloc) { // avoid duplicates
            if (!strOff.containsKey(s.name)) {
                strOff.put(s.name, shstr.size());
                shstr.write(s.name.getBytes(StandardCharsets.US_ASCII));
                shstr.write(0);
            }
        }
        int shstrtabNameOff = shstr.size();
        shstr.write(".shstrtab".getBytes(StandardCharsets.US_ASCII));
        shstr.write(0);
        byte[] shstrBytes = shstr.toByteArray();

        /* -------- Lay out payloads (8‑byte alignment for DWARF/RELA) -------- */
        int cur = EH_SIZE;
        Map<String, Integer> payloadOff = new LinkedHashMap<>();

        for (SectionData s : regular) {
            cur = align(cur, 8);
            payloadOff.put(s.name, cur);
            cur += s.contents.length;
        }
        for (SectionData s : reloc) { // RELA is 8‑byte aligned too
            cur = align(cur, 8);
            payloadOff.put(s.name, cur);
            cur += s.contents.length;
        }
        int shstrOff = align(cur, 1);
        int shtOff = align(shstrOff + shstrBytes.length, 8);

        /* -------- Section‑header bookkeeping -------------------------------- */
        int shCount = 1 // [0] SHT_NULL
                + regular.size()
                + reloc.size()
                + 1; // .shstrtab
        int shstrndx = shCount - 1; // last header written

        /* -------- Allocate output buffer ----------------------------------- */
        int fileSize = shtOff + shCount * SH_SIZE;
        if (fileSize > 0x7fffffff)
            throw new IOException("side‑car too large for ByteBuffer (" + fileSize + " bytes)");
        ByteBuffer b = ByteBuffer.allocate(fileSize);
        b.order(bigEndian ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);

        /* -------- ELF header ------------------------------------------------ */
        short eMachine = elfMachine(currentProgram.getLanguage().getProcessor().toString());
        int eFlags = elfFlags(eMachine);

        b.put(new byte[] {
                0x7f, 'E', 'L', 'F', // EI_MAG
                2, // EI_CLASS = 64‑bit
                (byte) (bigEndian ? 2 : 1), // EI_DATA
                1, // EI_VERSION
                0, 0, // EI_OSABI / EI_ABIVERSION
                0, 0, 0, 0, 0, 0, 0 // EI_PAD[7]
        });
        b.putShort((short) 1); // e_type = ET_REL
        b.putShort(eMachine); // e_machine
        b.putInt(1); // e_version
        b.putLong(0); // e_entry
        b.putLong(0); // e_phoff
        b.putLong(shtOff); // e_shoff
        b.putInt(eFlags); // e_flags
        b.putShort((short) EH_SIZE); // e_ehsize
        b.putShort((short) 0); // e_phentsize
        b.putShort((short) 0); // e_phnum
        b.putShort((short) SH_SIZE); // e_shentsize
        b.putShort((short) shCount); // e_shnum
        b.putShort((short) shstrndx); // e_shstrndx

        /* -------- Payloads -------------------------------------------------- */
        for (SectionData s : regular) {
            pad(b, payloadOff.get(s.name));
            b.put(s.contents);
        }
        for (SectionData s : reloc) {
            pad(b, payloadOff.get(s.name));
            b.put(s.contents);
        }
        pad(b, shstrOff);
        b.put(shstrBytes);

        /* -------- Section‑header table ------------------------------------- */
        pad(b, shtOff);

        /* [0] SHT_NULL */
        putSh(b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

        /* [1 …] DWARF (SHT_PROGBITS) */
        Map<String, Integer> headerIndex = new HashMap<>();
        int idx = 1;
        for (SectionData s : regular) {
            headerIndex.put(s.name, idx);
            putSh(b,
                    strOff.get(s.name), // sh_name
                    1, // SHT_PROGBITS
                    0,
                    0,
                    payloadOff.get(s.name),
                    s.contents.length,
                    0, 0,
                    8, // sh_addralign
                    0); // sh_entsize
            idx++;
        }

        /* relocation sections (SHT_RELA) — link = header index of target */
        for (SectionData s : reloc) {
            boolean isRela = s.name.startsWith(".rela.");
            int shtype = isRela ? 4 /* SHT_RELA */ : 9 /* SHT_REL */;
            int entsz = entrySize(isRela, is64);

            // ".rela.debug_info" → ".debug_info"
            String target = s.name.replaceFirst("^\\.rela?\\.", ".");
            int shInfo = headerIndex.getOrDefault(target, 0);

            putSh(b,
                    strOff.get(s.name), // sh_name
                    shtype,
                    0,
                    0,
                    payloadOff.get(s.name),
                    s.contents.length,
                    0,
                    shInfo,
                    8,
                    entsz);
        }

        /* .shstrtab */
        putSh(b,
                shstrtabNameOff,
                3, // SHT_STRTAB
                0, 0,
                shstrOff,
                shstrBytes.length,
                0, 0,
                1, // sh_addralign
                0); // sh_entsize

        /* -------- Write file ---------------------------------------------- */
        try (FileOutputStream fos = new FileOutputStream(currentProgram.getExecutablePath() + ".dbg")) {
            fos.write(b.array());
        }
    }

    /* ------------------------------------------------------------------ */
    /* misc helpers */
    /* ------------------------------------------------------------------ */

    private List<Range> collectExecutableRanges() {
        List<Range> out = new ArrayList<>();
        for (AddressRange r : currentProgram.getMemory().getExecuteSet())
            out.add(new Range(r.getMinAddress().getUnsignedOffset(), r.getLength()));
        return out;
    }

    private static int align(int value, int align) {
        return ((value + align - 1) / align) * align;
    }

    private static void pad(ByteBuffer b, int tgt) {
        while (b.position() < tgt)
            b.put((byte) 0);
    }

    private static int entrySize(boolean rela, boolean is64) {
        return is64
                ? (rela ? 24 : 16) // 64-bit table sizes
                : (rela ? 12 : 8); // 32-bit table sizes
    }

    private static void putSh(ByteBuffer b, int name, int type, long flags,
            long addr, long off, long size,
            int link, int info, int align, long entsize) {
        b.putInt(name);
        b.putInt(type);
        b.putLong(flags);
        b.putLong(addr);
        b.putLong(off);
        b.putLong(size);
        b.putInt(link);
        b.putInt(info);
        b.putLong(align);
        b.putLong(entsize);
    }

    private static String getAbi(Program p) {
        int ps = p.getDefaultPointerSize();
        return switch (p.getLanguage().getProcessor().toString()) {
            case "ARM" -> "arm";
            case "AArch64" -> "arm64";
            case "PowerPC" -> ps <= 4 ? "ppc" : "ppc64";
            case "MIPS" -> "mips";
            case "x86" -> ps <= 4 ? "x86" : "x86_64";
            default -> "unknown";
        };
    }
}
