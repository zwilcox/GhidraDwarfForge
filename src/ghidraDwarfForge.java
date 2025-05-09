// ghidraDwarfForge.java
// Creates a minimal ELF with a .debug_aranges section covering the current program.
// @author  zwilcox
// @category  DWARF
// @keybinding
// @menupath
// @toolbar

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.format.elf.ElfConstants;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.util.exception.CancelledException;

import java.io.*;
import java.nio.*;
import java.nio.channels.FileChannel;
import java.util.*;

public class ghidraDwarfForge extends GhidraScript {

    class Range {
        final long start;
        final long length;

        Range(long s, long l) {
            start = s;
            length = l;
        }
    }

    @Override
    public void run() throws Exception {

        println("initializing!");
        int pointerSize = currentProgram.getDefaultPointerSize();
        String processorStr = currentProgram.getLanguage().getProcessor().toString();

        Endian endian = currentProgram.getLanguage().getLanguageDescription().getEndian();

        println("Pointer size: " + pointerSize);
        println("Endianness: " + endian.toString());
        println("Processor: " + processorStr);

        int bitNessFlags = LibDwarf.DW_DLC_POINTER32 | LibDwarf.DW_DLC_OFFSET32;
        int addressSize = 4;

        if (pointerSize > 4) {
            bitNessFlags = LibDwarf.DW_DLC_POINTER64 | LibDwarf.DW_DLC_OFFSET64;
            addressSize = 8;
        }

        int endiannessFlag = LibDwarf.DW_DLC_TARGET_LITTLEENDIAN;
        if (endian == Endian.BIG) {
            endiannessFlag = LibDwarf.DW_DLC_TARGET_BIGENDIAN;
        }

        String abi = getProgramLibdwarfAbiName(currentProgram);

        println("=== Program Information ===");
        println(String.format("Endianness\t: %s-endian",
            endian == Endian.BIG ? "Big" : "Little"));
        println(String.format("Pointer size\t: %d bytes", pointerSize));
        println("ABI\t\t: " + abi);

        println("Generating arange section");
        List<Range> ranges = collectExecutableRanges();
        println("Collected " + ranges.size() + " contiguous executable range(s).");
        byte[] arangesBytes = buildDebugAranges(ranges, addressSize, endian);
        println(".debug_aranges size: " + arangesBytes.length + " bytes");

        println("Writing minimal elf file.");
        File outFile = buildMinimalElf(arangesBytes, addressSize, endian);
        println("\nWrote minimal ELF: " + outFile.getAbsolutePath());

    }

    /**
     * Walk the program's executable memory, flattening to contiguous ranges.
     */
    private List<Range> collectExecutableRanges() throws CancelledException {
        AddressSetView exec = currentProgram.getMemory().getExecuteSet();
        AddressRangeIterator it = exec.getAddressRanges(true);
        List<Range> list = new ArrayList<>();
        while (it.hasNext()) {
            monitor.checkCancelled();
            AddressRange r = it.next();
            list.add(new Range(r.getMinAddress().getUnsignedOffset(),
                r.getLength()));
        }
        return list;
    }

    /**
    * Build DWARF .debug_aranges section for a single CU (header-offset 0).
    *                      ┌────────────────── unit_length (excl. itself)
    *  [4] unit_length →   │ 0xYYYYYYYY
    *  [2] version         │ 0x0002
    *  [4] debug_info_off  │ 0x00000000
    *  [1] address_size    │ 4 or 8
    *  [1] seg_size (0)    │ 0x00
    *    ...padding to multiple of (addrSize*2)...
    *  [(addrSize*2)*N] (addr,len) tuples
    *  [(addrSize*2)] 0/0 terminator
    */
    private byte[] buildDebugAranges(List<Range> ranges,
            int addrSize,
            Endian endian) throws IOException {

        try (ByteArrayOutputStream byteArray = new ByteArrayOutputStream();
                DataOutputStream dataOutput = new DataOutputStream(byteArray)) {

            /* ---- prologue ---- */
            writeUInt(dataOutput, 0, 4, endian);        // placeholder for unit_length
            writeUInt(dataOutput, 2, 2, endian);        // version
            writeUInt(dataOutput, 0, 4, endian);        // debug_info_offset (single CU at 0)
            writeUInt(dataOutput, addrSize, 1, endian); // address_size
            writeUInt(dataOutput, 0, 1, endian);        // segment_selector_size

            /* ---- pad to tuple alignment (addrSize * 2) ---- */
            int headerLen = dataOutput.size();
            int tupleAlign = addrSize * 2;
            int padNeeded = (tupleAlign - (headerLen % tupleAlign)) % tupleAlign;
            for (int i = 0; i < padNeeded; i++)
                dataOutput.write(0);

            /* ---- range tuples ---- */
            for (Range r : ranges) {
                writeUInt(dataOutput, r.start, addrSize, endian);
                writeUInt(dataOutput, r.length, addrSize, endian);
            }

            /* ---- terminator tuple ---- */
            writeUInt(dataOutput, 0, addrSize, endian);
            writeUInt(dataOutput, 0, addrSize, endian);

            /* ---- patch the initial unit_length field ---- */
            dataOutput.flush();                          // ensure all bytes are in baos
            byte[] section = byteArray.toByteArray();
            int unitLen = section.length - 4;  // exclude the length field itself
            patchUInt(section, 0, unitLen, 4, endian);

            return section;                       // streams auto-close here
        }
    }

    /**
    * Emit a minimal ELF that contains only:
    *   • [0] NULL section header
    *   • [1] .debug_aranges   (the bytes produced by buildDebugAranges)
    *   • [2] .shstrtab        (section-name string table)
    *
    * @return File handle to <orig-path>.dbg
    */
    /**
     * Emit a bare-bones ELF containing:
     *   • NULL section header
     *   • .debug_aranges  (bytes passed in)
     *   • .shstrtab       (section-name table)
     *
     * The file is written as <original-binary>.dbg and returned.
     */
    private File buildMinimalElf(byte[] aranges,
            int addrSize,
            Endian endian) throws IOException {

        boolean is64 = addrSize == 8;
        int elfHdrSize = is64 ? 64 : 52;
        int shEntSize = is64 ? 64 : 40;
        int sectionCount = 3;                   // NULL + aranges + shstrtab

        /* ---------- section-name string table --------------------------- */
        ByteArrayOutputStream shstr = new ByteArrayOutputStream();
        shstr.write(0);                                   // index 0 = NULL
        int offArangesName = shstr.size();
        shstr.write(".debug_aranges".getBytes());
        shstr.write(0);
        int offShstrName = shstr.size();
        shstr.write(".shstrtab".getBytes());
        shstr.write(0);
        byte[] shstrBytes = shstr.toByteArray();

        /* ---------- layout calculations --------------------------------- */
        int offArangesSec = elfHdrSize;                       // right after ELF header
        int offShstrtabSec = align(offArangesSec + aranges.length, 1);
        int offSHT = align(offShstrtabSec + shstrBytes.length, is64 ? 8 : 4);
        int fileSize = offSHT + sectionCount * shEntSize;

        /* ---------- build ELF image in memory --------------------------- */
        ByteBuffer buf = ByteBuffer.allocate(fileSize);
        buf.order(endian == Endian.BIG ? ByteOrder.BIG_ENDIAN
                : ByteOrder.LITTLE_ENDIAN);

        /* === ELF header (EI_OSABI defaults to 0 for 11.3) =============== */
        buf.put(new byte[] {
            0x7f, 'E', 'L', 'F',
            (byte) (is64 ? 2 : 1),                  // EI_CLASS
            (byte) (endian == Endian.BIG ? 2 : 1),  // EI_DATA
            1,                                     // EI_VERSION
            0,                                     // EI_OSABI  (System V)
            0, 0, 0, 0, 0, 0, 0                    // EI_ABIVERSION & padding
        });

        buf.putShort((short) 1);                                 // e_type = ET_REL
        buf.putShort(mapProcessorToEMachine(currentProgram));   // e_machine
        buf.putInt(1);                                          // e_version

        putAddr(buf, 0, is64);    // e_entry
        putAddr(buf, 0, is64);    // e_phoff  (no program headers)
        putAddr(buf, offSHT, is64);    // e_shoff

        buf.putInt(0);                                           // e_flags
        buf.putShort((short) elfHdrSize);                         // e_ehsize
        buf.putShort((short) 0);                                  // e_phentsize
        buf.putShort((short) 0);                                  // e_phnum
        buf.putShort((short) shEntSize);                          // e_shentsize
        buf.putShort((short) sectionCount);                       // e_shnum
        buf.putShort((short) 2);                                  // e_shstrndx

        /* === section data ============================================== */
        padTo(buf, offArangesSec);
        buf.put(aranges);
        padTo(buf, offShstrtabSec);
        buf.put(shstrBytes);

        /* === section headers =========================================== */
        padTo(buf, offSHT);

        // [0] NULL
        putSh(buf, is64, 0, 0, 0, 0, 0, 0, 0, 0, 0);

        // [1] .debug_aranges
        putSh(buf, is64,
            offArangesName,
            1,                 // SHT_PROGBITS
            0, 0,
            offArangesSec,
            aranges.length,
            0, 0, 1);

        // [2] .shstrtab
        putSh(buf, is64,
            offShstrName,
            3,                 // SHT_STRTAB
            0, 0,
            offShstrtabSec,
            shstrBytes.length,
            0, 0, 1);

        /* ---------- write to disk -------------------------------------- */
        File out = new File(currentProgram.getExecutablePath() + ".dbg");
        try (FileOutputStream fos = new FileOutputStream(out);
                FileChannel fc = fos.getChannel()) {

            buf.position(0);
            fc.write(buf);
        }
        return out;
    }

    String getProgramLibdwarfAbiName(Program prog) {
        int pointerSize = prog.getDefaultPointerSize();
        switch (prog.getLanguage().getProcessor().toString()) {
            case "ARM":
                return "arm";
            case "AArch64":
                return "arm64";
            case "PowerPC":
                return pointerSize <= 4 ? "ppc" : "ppc64";
            case "MIPS":
                return "mips";
            case "x86":
            default:
                return pointerSize <= 4 ? "x86" : "x86_64";
        }
    }

    private int align(int v, int a) {
        return (v + (a - 1)) & ~(a - 1);
    }

    /** Write 4- or 8-byte address / offset depending on is64 flag. */
    private void putAddr(ByteBuffer b, long v, boolean is64) {
        if (is64)
            b.putLong(v);
        else
            b.putInt((int) v);
    }

    private void padTo(ByteBuffer buff, int target) {
        while (buff.position() < target)
            buff.put((byte) 0);
    }

    private void writeUInt(DataOutputStream outputStream, long value, int size, Endian endian)
            throws IOException {
        for (int i = 0; i < size; i++) {
            int shift = endian == Endian.BIG ? (size - 1 - i) * 8 : i * 8;
            outputStream.write((int) ((value >> shift) & 0xff));
        }
    }

    /**
     * Write an ELF section header entry. Works for 32- or 64-bit.
     */
    private void putSh(ByteBuffer buf, boolean is64,
            long name, long type, long flags, long addr,
            long off, long size, long link, long info, long addralign) {

        if (is64) {
            buf.putInt((int) name);
            buf.putInt((int) type);
            buf.putLong(flags);
            buf.putLong(addr);
            buf.putLong(off);
            buf.putLong(size);
            buf.putInt((int) link);
            buf.putInt((int) info);
            buf.putLong(addralign);
            buf.putLong(0);            // sh_entsize
        }
        else {
            buf.putInt((int) name);
            buf.putInt((int) type);
            buf.putInt((int) flags);
            buf.putInt((int) addr);
            buf.putInt((int) off);
            buf.putInt((int) size);
            buf.putInt((int) link);
            buf.putInt((int) info);
            buf.putInt((int) addralign);
            buf.putInt(0);          // sh_entsize
        }
    }

    /**
     * Map Ghidra processor ? e_machine.
     */
    private short mapProcessorToEMachine(Program prog) {
        String p = prog.getLanguage().getProcessor().toString();
        int ps = prog.getDefaultPointerSize();
        switch (p) {
            case "ARM":
                return ElfConstants.EM_ARM;
            case "AArch64":
                return ElfConstants.EM_AARCH64;
            case "MIPS":
                return ElfConstants.EM_MIPS;
            case "PowerPC":
                return (ps <= 4 ? ElfConstants.EM_PPC : ElfConstants.EM_PPC64);
            case "x86":
                return (ps <= 4 ? ElfConstants.EM_386 : ElfConstants.EM_X86_64);
            default:
                return (short) 0;      // EM_NONE
        }
    }

    private void patchUInt(byte[] arr, int off, long value, int size, Endian endian) {
        for (int i = 0; i < size; i++) {
            int shift = endian == Endian.BIG ? (size - 1 - i) * 8 : i * 8;
            arr[off + i] = (byte) ((value >> shift) & 0xff);
        }
    }

}
