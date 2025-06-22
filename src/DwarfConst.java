import com.sun.jna.Pointer;

public class DwarfConst {

    private DwarfConst() {
    } // prevent instantiation

    /* .debug_info */
    public static final int DW_SECT_INFO = 0;
    /* .debug_abbrev */
    public static final int DW_SECT_ABBREV = 1;
    /* .debug_aranges */
    public static final int DW_SECT_ARANGES = 2;

    public static final int DW_SECT_REL_ARANGES = 0x1a;
    public static final int DW_SECT_REL_INFO = 0x19;
    // .rela.debug_info
    public static final int DW_SECT_RELA_INFO = 0x1b;
    // .rela.debug_aranges
    public static final int DW_SECT_RELA_ARANGES = 0x1c;

    // success
    public static final int DW_DLV_OK = 0;
    public static final int DW_DLV_NO_ENTRY = -1;
    public static final int DW_DLV_ERROR = -2;

    /* ---- attribute, tag, form, op ---- */
    public static final int DW_ATE_address = 0x01;
    public static final int DW_ATE_boolean = 0x02;
    public static final int DW_AT_name = 0x03;
    public static final int DW_AT_byte_size = 0x0b;
    public static final int DW_AT_high_pc = 0x12;
    public static final int DW_AT_low_pc = 0x11;
    public static final int DW_FORM_string = 0x08;
    public static final int DW_TAG_compile_unit = 0x11;
    public static final int DW_AT_language = 0x13;
    public static final int DW_AT_comp_dir = 0x1b;
    public static final int DW_AT_producer = 0x25;

    /* ---- access modes ---- */
    public static final int DW_DLC_READ = 2;
    public static final int DW_DLC_WRITE = 1;

    /* pointer/offset size flags */
    public static final int DW_DLC_POINTER32 = 0x20000000;
    public static final int DW_DLC_OFFSET32 = 0x00010000;
    public static final int DW_DLC_POINTER64 = 0x40000000;
    public static final int DW_DLC_OFFSET64 = 0x10000000;

    /* target endianness */
    public static final int DW_DLC_TARGET_LITTLEENDIAN = 0x00100000;
    public static final int DW_DLC_TARGET_BIGENDIAN = 0x08000000;

    /* ---- special values ---- */
    public static final Pointer DW_DLV_BADADDR = Pointer.createConstant(-1);
    public static final long DW_DLV_NOCOUNT = -1L;

    public static final int DW_DLC_SYMBOLIC_RELOCATIONS = 0x04000000;

}
