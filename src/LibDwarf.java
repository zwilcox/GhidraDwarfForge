import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Platform;
import com.sun.jna.Pointer;
import com.sun.jna.PointerType;
import com.sun.jna.ptr.LongByReference;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.ptr.ShortByReference;


public interface LibDwarf extends Library {

	
	public static final int DW_ATE_address = 0x01;
    public static final int DW_ATE_boolean = 0x02;
    public static final int DW_ATE_complex_float = 0x03;
    public static final int DW_ATE_float = 0x04;
    public static final int DW_ATE_signed = 0x05;
    public static final int DW_ATE_signed_char = 0x06;
    public static final int DW_ATE_unsigned = 0x07;
    public static final int DW_ATE_unsigned_char = 0x08;
    public static final int DW_AT_byte_size = 0x0b;
    public static final int DW_AT_const_value = 0x1c;
    public static final int DW_AT_count = 0x37;
    public static final int DW_AT_data_member_location = 0x38;
    public static final int DW_AT_decl_file = 0x3a;
    public static final int DW_AT_decl_line = 0x3b;
    public static final int DW_AT_encoding = 0x3e;
    public static final int DW_AT_frame_base = 0x40;
    public static final int DW_AT_high_pc = 0x12;
    public static final int DW_AT_linkage_name = 0x6e;
    public static final int DW_AT_location = 0x02;
    public static final int DW_AT_low_pc = 0x11;
    public static final int DW_AT_type = 0x49;
    public static final int DW_DLC_OFFSET32 = 0x00010000;
    public static final int DW_DLC_OFFSET64 = 0x10000000;
    public static final int DW_DLC_POINTER32 = 0x20000000;
    public static final int DW_DLC_POINTER64 = 0x40000000;
    public static final int DW_DLC_SYMBOLIC_RELOCATIONS = 0x04000000;
    public static final int DW_DLC_TARGET_LITTLEENDIAN = 0x00100000;
    public static final int DW_DLC_TARGET_BIGENDIAN = 0x08000000;
    public static final int DW_DLC_WRITE = 1;
    public static final int DW_DLC_READ = 2;
    public static final Pointer DW_DLV_BADADDR = new Pointer((~0));
    public static final long DW_DLV_NOCOUNT = -1;
    public static final int DW_DLV_OK = 0;
    public static final int DW_FORM_string = 0x08;
    public static final int DW_FRAME_HIGHEST_NORMAL_REGISTER = 188;
    public static final int DW_FRAME_LAST_REG_NUM = DW_FRAME_HIGHEST_NORMAL_REGISTER + 3;
    public static final int DW_OP_breg0 = 0x70;
    public static final int DW_OP_breg1 = 0x71;
    public static final int DW_OP_breg2 = 0x72;
    public static final int DW_OP_breg3 = 0x73;
    public static final int DW_OP_breg4 = 0x74;
    public static final int DW_OP_breg5 = 0x75;
    public static final int DW_OP_breg6 = 0x76;
    public static final int DW_OP_breg7 = 0x77;
    public static final int DW_OP_breg8 = 0x78;
    public static final int DW_OP_breg9 = 0x79;
    public static final int DW_OP_breg10 = 0x7a;
    public static final int DW_OP_breg11 = 0x7b;
    public static final int DW_OP_breg12 = 0x7c;
    public static final int DW_OP_breg13 = 0x7d;
    public static final int DW_OP_breg14 = 0x7e;
    public static final int DW_OP_breg15 = 0x7f;
    public static final int DW_OP_breg16 = 0x80;
    public static final int DW_OP_breg17 = 0x81;
    public static final int DW_OP_breg18 = 0x82;
    public static final int DW_OP_breg19 = 0x83;
    public static final int DW_OP_breg20 = 0x84;
    public static final int DW_OP_breg21 = 0x85;
    public static final int DW_OP_breg22 = 0x86;
    public static final int DW_OP_breg23 = 0x87;
    public static final int DW_OP_breg24 = 0x88;
    public static final int DW_OP_breg25 = 0x89;
    public static final int DW_OP_breg26 = 0x8a;
    public static final int DW_OP_breg27 = 0x8b;
    public static final int DW_OP_breg28 = 0x8c;
    public static final int DW_OP_breg29 = 0x8d;
    public static final int DW_OP_breg30 = 0x8e;
    public static final int DW_OP_breg31 = 0x8f;
    public static final int DW_OP_call_frame_cfa = 0x9c;
    public static final int DW_OP_fbreg = 0x91;
    public static final int DW_OP_plus_uconst = 0x23;
    public static final int DW_OP_regx = 0x90;
    public static final int DW_TAG_array_type = 0x01;
    public static final int DW_TAG_base_type = 0x24;
    public static final int DW_TAG_compile_unit = 0x11;
    public static final int DW_TAG_enumeration_type = 0x04;
    public static final int DW_TAG_enumerator = 0x28;
    public static final int DW_TAG_formal_parameter = 0x05;
    public static final int DW_TAG_member = 0x0d;
    public static final int DW_TAG_pointer_type = 0x0f;
    public static final int DW_TAG_structure_type = 0x13;
    public static final int DW_TAG_subprogram = 0x2e;
    public static final int DW_TAG_subrange_type = 0x21;
    public static final int DW_TAG_variable = 0x34;

    LibDwarf INSTANCE = Native.load(Platform.isWindows() ? "libdwarf" : "dwarf",
            LibDwarf.class);

    public static class Dwarf_Debug extends PointerType {
        /** no-arg ctor required by JNA */
        public Dwarf_Debug() {
        }

        /** wrap an existing native pointer */
        public Dwarf_Debug(Pointer p) {
            super(p);
        }
    }

    public static class Dwarf_Error extends PointerType {
        public Dwarf_Error() {
        }

        public Dwarf_Error(Pointer p) {
            super(p);
        }
    }


    /**
     * int dwarf_init(int fd, int access, Dwarf_Handler errhand, Dwarf_Ptr errarg,
     * Dwarf_Debug *dbg, Dwarf_Error *error);
     */
    int dwarf_init(int fd,
            int access,
            Pointer errhand, // use NULL → default handler
            Pointer errarg, // user data – ignored here
            PointerByReference dbg, // (out)
            PointerByReference error);

    /** void dwarf_finish(Dwarf_Debug dbg, Dwarf_Error *error); */
    int dwarf_finish(Dwarf_Debug dbg,
            PointerByReference error);

    /**
     * int dwarf_next_cu_header_d(Dwarf_Debug dbg,
     * Dwarf_Unsigned *cu_header_length,
     * Dwarf_Half *version_stamp,
     * Dwarf_Off *abbr_offset,
     * Dwarf_Half *addr_size,
     * Dwarf_Unsigned *next_cu_header_offset,
     * Dwarf_Half *header_cu_type,
     * Dwarf_Error *error);
     */
    int dwarf_next_cu_header_d(Dwarf_Debug dbg,
            LongByReference cu_header_length,
            ShortByReference version_stamp,
            LongByReference abbr_offset,
            ShortByReference addr_size,
            LongByReference next_cu_header_offset,
            ShortByReference header_cu_type,
            PointerByReference error);

    /*
     * ---------------------------------------------------------------------
     * Error helpers
     * ------------------------------------------------------------------
     */
    /** const char* dwarf_errmsg(Dwarf_Error err); */
    String dwarf_errmsg(Dwarf_Error error);

    /** unsigned long dwarf_errno(Dwarf_Error err); */
    long dwarf_errno(Dwarf_Error error);

    final class Wrapper {
        private final LibDwarf api = LibDwarf.INSTANCE;
        private final Dwarf_Debug dbg;

        public Wrapper(int fd) throws LibDwarfException {
            PointerByReference dbgRef = new PointerByReference();
            int res = api.dwarf_init(fd, DW_DLC_READ, null, null, dbgRef, null);
            if (res != 0) {
                throw new LibDwarfException("dwarf_init failed: " + res);
            }
            this.dbg = new Dwarf_Debug(dbgRef.getValue());
        }

        public void close() throws LibDwarfException {
            int res = api.dwarf_finish(dbg, null);
            if (res != 0) {
                throw new LibDwarfException("dwarf_finish failed: " + res);
            }
        }
    }

    class LibDwarfException extends Exception {
        public LibDwarfException(String msg) {
            super(msg);
        }
    }
}
