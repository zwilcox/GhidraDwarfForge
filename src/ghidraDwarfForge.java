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

import com.sun.jna.Pointer;
import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.ptr.IntByReference;

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

        println("Building DWARF sections with libdwarf");

        List<Range> ranges = collectExecutableRanges();
        println("Collected " + ranges.size() + " contiguous executable range(s).");

        int dlcFlags = bitNessFlags | endiannessFlag;
        println(String.format("libdwarf dlc flags: 0x%02x", dlcFlags));

        // build DWARF sections with libdwarf
        Map<String, byte[]> dwarfSecs = buildDwarfSections(ranges, dlcFlags, addressSize);

        println("Writing minimal elf file.");
        File outFile = buildMinimalElf(dwarfSecs, addressSize, endian);

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
     * ┌────────────────── unit_length (excl. itself)
     * [4] unit_length → │ 0xYYYYYYYY
     * [2] version │ 0x0002
     * [4] debug_info_off │ 0x00000000
     * [1] address_size │ 4 or 8
     * [1] seg_size (0) │ 0x00
     * ...padding to multiple of (addrSize*2)...
     * [(addrSize*2)*N] (addr,len) tuples
     * [(addrSize*2)] 0/0 terminator
     */
    private byte[] buildDebugAranges(List<Range> ranges,
            int addrSize,
            Endian endian) throws IOException {

        try (ByteArrayOutputStream byteArray = new ByteArrayOutputStream();
                DataOutputStream dataOutput = new DataOutputStream(byteArray)) {

            /* ---- prologue ---- */
            writeUInt(dataOutput, 0, 4, endian); // placeholder for unit_length
            writeUInt(dataOutput, 2, 2, endian); // version
            writeUInt(dataOutput, 0, 4, endian); // debug_info_offset (single CU at 0)
            writeUInt(dataOutput, addrSize, 1, endian); // address_size
            writeUInt(dataOutput, 0, 1, endian); // segment_selector_size

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
            dataOutput.flush(); // ensure all bytes are in baos
            byte[] section = byteArray.toByteArray();
            int unitLen = section.length - 4; // exclude the length field itself
            patchUInt(section, 0, unitLen, 4, endian);

            return section; // streams auto-close here
        }
    }

    /**
     * Ask libdwarf to produce .debug_* sections for the given address ranges.
     *
     * @param ranges      contiguous executable ranges we discovered
     * @param dlcFlags    DW_DLC_* pointer-width + endianness bits
     * @param addressSize 4 or 8
     * @return map: section name → raw bytes
     */
    private Map<String, byte[]> buildDwarfSections(List<Range> ranges,
            int dlcFlags,
            int addressSize) throws IOException {

        Map<String, byte[]> dwarfSections = new HashMap<>();

        /* ---------- initialise producer ---------------------------------- */
        PointerByReference dbgRef = new PointerByReference();

        int err = LibDwarf.INSTANCE.dwarf_producer_init_b(
            LibDwarf.DW_DLC_WRITE | dlcFlags, // all flags in first param
            0, // 2nd param reserved in v0.6+
            null, null, null, // callbacks / error handler
            dbgRef); // out pointer

        if (err != 0)
            throw new IOException("dwarf_producer_init_b failed: " + err);

        Pointer dbgPtr = dbgRef.getValue();
        LibDwarf.Dwarf_P_Debug dbg = new LibDwarf.Dwarf_P_Debug(dbgPtr);

        /* ---------- create CU DIE + mandatory attributes ----------------- */
        LibDwarf.Dwarf_P_Die cuDie = LibDwarf.INSTANCE.dwarf_new_die(
            dbg, LibDwarf.DW_TAG_compile_unit,
            null, null, null); // sibling, parent, child

        // language = DW_LANG_C89
        LibDwarf.INSTANCE.dwarf_add_AT_unsigned_const(
            dbg, cuDie, LibDwarf.DW_AT_language, 0x0001, 0);

        long low = ranges.get(0).start;
        long high = ranges.stream()
                .mapToLong(r -> r.start + r.length)
                .max()
                .orElse(low);

        LibDwarf.INSTANCE.dwarf_add_AT_unsigned_const(
            dbg, cuDie, LibDwarf.DW_AT_low_pc, low, addressSize);
        LibDwarf.INSTANCE.dwarf_add_AT_unsigned_const(
            dbg, cuDie, LibDwarf.DW_AT_high_pc, high, addressSize);

        /* ---------- arange tuples ---------------------------------------- */
        long cuOffset = LibDwarf.INSTANCE.dwarf_dieoffset(cuDie);

        for (Range r : ranges) {
            LibDwarf.INSTANCE.dwarf_add_arange_b(
                dbg, r.start, r.length,
                cuOffset, addressSize,
                0 /* seg size */, null);
        }

        /* ---------- finish & collect section blobs ----------------------- */
        PointerByReference namesRef = new PointerByReference();
        PointerByReference dataRef = new PointerByReference();
        IntByReference sizesRef = new IntByReference();
        IntByReference countRef = new IntByReference();

        err = LibDwarf.INSTANCE.dwarf_producer_finish_a(
            dbgPtr, namesRef, dataRef, sizesRef, countRef);

        if (err != 0)
            throw new IOException("dwarf_producer_finish_a failed: " + err);

        int count = countRef.getValue();
        Pointer namesPtr = namesRef.getValue();
        Pointer dataPtr = dataRef.getValue();
        Pointer sizePtr = sizesRef.getPointer();

        for (int i = 0; i < count; i++) {
            String secName = namesPtr
                    .getPointer((long) i * Native.POINTER_SIZE)
                    .getString(0);

            long secSize = sizePtr
                    .getLong((long) i * NativeLong.SIZE);

            byte[] bytes = dataPtr
                    .getPointer((long) i * Native.POINTER_SIZE)
                    .getByteArray(0, (int) secSize);

            dwarfSections.put(secName, bytes);
        }

        /* ---------- free producer buffers -------------------------------- */
        LibDwarf.INSTANCE.dwarf_producer_finish(dbgPtr);

        return dwarfSections;
    }

    /**
     * Build a minimal ELF side-car (<orig>.dbg) that contains every DWARF
     * section provided in {@code secMap} plus a .shstrtab. All sections are
     * emitted as SHT_PROGBITS with no flags; that is sufficient for GDB/LLDB.
     *
     * @param secMap   map: section‐name → bytes (must include “.” prefix)
     * @param addrSize 4 or 8 (pointer size)
     * @param endian   Endian.LITTLE / Endian.BIG
     * @return File written next to the original executable
     */
    private File buildMinimalElf(Map<String, byte[]> secMap,
            int addrSize,
            Endian endian) throws IOException {

        /* ------------------------------------------------ layout constants */
        boolean is64 = addrSize == 8;
        int elfHdrSize = is64 ? 64 : 52;
        int shEntSize = is64 ? 64 : 40;
        int sectionCount = 1 /* NULL */ + secMap.size() + 1 /* shstrtab */;

        /* ------------------------------------------------ .shstrtab build */
        ByteArrayOutputStream shstr = new ByteArrayOutputStream();
        shstr.write(0); // index 0 == NULL

        // keep insertion order for deterministic output
        Map<String, Integer> nameOffset = new LinkedHashMap<>();
        for (String s : secMap.keySet()) {
            nameOffset.put(s, shstr.size());
            shstr.write(s.getBytes());
            shstr.write(0);
        }
        int offShstrName = shstr.size();
        shstr.write(".shstrtab".getBytes());
        shstr.write(0);
        byte[] shstrBytes = shstr.toByteArray();

        /* ------------------------------------------------ data offsets */
        Map<String, Integer> secOffset = new LinkedHashMap<>();
        int currOff = elfHdrSize;

        for (String s : secMap.keySet()) {
            currOff = align(currOff, 1); // DWARF needs only byte align
            secOffset.put(s, currOff);
            currOff += secMap.get(s).length;
        }
        int offShstrtabSec = align(currOff, 1);
        int offSHT = align(offShstrtabSec + shstrBytes.length,
            is64 ? 8 : 4);
        int fileSize = offSHT + sectionCount * shEntSize;

        /* ------------------------------------------------ buffer & order */
        ByteBuffer buf = ByteBuffer.allocate(fileSize);
        buf.order(endian == Endian.BIG ? ByteOrder.BIG_ENDIAN
                : ByteOrder.LITTLE_ENDIAN);

        /* ================= ELF header ==================================== */
        buf.put(new byte[] {
            0x7f, 'E', 'L', 'F',
            (byte) (is64 ? 2 : 1), // EI_CLASS
            (byte) (endian == Endian.BIG ? 2 : 1), // EI_DATA
            1, 0, // EI_VERSION, EI_OSABI=0(SysV)
            0, 0, 0, 0, 0, 0, 0 // EI_ABIVERSION & padding
        });
        buf.putShort((short) 1); // ET_REL
        buf.putShort(mapProcessorToEMachine(currentProgram)); // e_machine
        buf.putInt(1); // e_version
        putAddr(buf, 0, is64); // e_entry
        putAddr(buf, 0, is64); // e_phoff
        putAddr(buf, offSHT, is64); // e_shoff
        buf.putInt(0); // e_flags
        buf.putShort((short) elfHdrSize); // e_ehsize
        buf.putShort((short) 0);
        buf.putShort((short) 0); // ph size/num
        buf.putShort((short) shEntSize);
        buf.putShort((short) sectionCount);
        buf.putShort((short) (sectionCount - 1)); // shstrtab index (last one added)

        /* ================= section data ================================== */
        for (String s : secMap.keySet()) {
            padTo(buf, secOffset.get(s));
            buf.put(secMap.get(s));
        }
        padTo(buf, offShstrtabSec);
        buf.put(shstrBytes);

        /* ================= section headers =============================== */
        padTo(buf, offSHT);

        /* [0] NULL -------------------------------------------------------- */
        putSh(buf, is64, 0, 0, 0, 0, 0, 0, 0, 0, 0);

        /* [1..N] DWARF sections ------------------------------------------ */
        for (String s : secMap.keySet()) {
            putSh(buf, is64,
                nameOffset.get(s), // sh_name
                1, // SHT_PROGBITS
                0, 0, // flags, addr
                secOffset.get(s), // sh_offset
                secMap.get(s).length, // sh_size
                0, 0, 1); // link, info, align
        }

        /* [.shstrtab] ----------------------------------------------------- */
        putSh(buf, is64,
            offShstrName,
            3, // SHT_STRTAB
            0, 0,
            offShstrtabSec,
            shstrBytes.length,
            0, 0, 1);

        /* ================= write to disk ================================ */
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
            buf.putLong(0); // sh_entsize
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
            buf.putInt(0); // sh_entsize
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
                return (short) 0; // EM_NONE
        }
    }

    private void patchUInt(byte[] arr, int off, long value, int size, Endian endian) {
        for (int i = 0; i < size; i++) {
            int shift = endian == Endian.BIG ? (size - 1 - i) * 8 : i * 8;
            arr[off + i] = (byte) ((value >> shift) & 0xff);
        }
    }

}
