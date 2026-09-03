package ghidradwarfforge.nativeapi;

/**
 * Constants audited against libdwarf 2.3.2 dwarf.h and libdwarfp.h.
 *
 * <p>This intentionally contains only values used by the current smoke test.
 * Expand it only while adding a tested producer operation.</p>
 */
public final class DwarfConstants {
    private DwarfConstants() {
    }

    public static final int DW_DLV_OK = 0;
    public static final int DW_DLV_NO_ENTRY = -1;
    public static final int DW_DLV_ERROR = 1;

    public static final int DW_FORM_STRP = 0x0e;

    public static final long DW_DLC_POINTER64 = 0x40000000L;
    public static final long DW_DLC_POINTER32 = 0x20000000L;
    public static final long DW_DLC_OFFSET32 = 0x00010000L;
    public static final long DW_DLC_SYMBOLIC_RELOCATIONS = 0x04000000L;
    public static final long DW_DLC_TARGET_BIGENDIAN = 0x08000000L;
    public static final long DW_DLC_TARGET_LITTLEENDIAN = 0x00100000L;

    public static final long DW_TAG_COMPILE_UNIT = 0x11L;
    public static final long DW_TAG_SUBPROGRAM = 0x2eL;
    public static final long DW_TAG_ARRAY_TYPE = 0x01L;
    public static final long DW_TAG_ENUMERATION_TYPE = 0x04L;
    public static final long DW_TAG_FORMAL_PARAMETER = 0x05L;
    public static final long DW_TAG_MEMBER = 0x0dL;
    public static final long DW_TAG_POINTER_TYPE = 0x0fL;
    public static final long DW_TAG_REFERENCE_TYPE = 0x10L;
    public static final long DW_TAG_STRUCTURE_TYPE = 0x13L;
    public static final long DW_TAG_SUBROUTINE_TYPE = 0x15L;
    public static final long DW_TAG_TYPEDEF = 0x16L;
    public static final long DW_TAG_UNION_TYPE = 0x17L;
    public static final long DW_TAG_UNSPECIFIED_PARAMETERS = 0x18L;
    public static final long DW_TAG_NAMESPACE = 0x39L;
    public static final long DW_TAG_SUBRANGE_TYPE = 0x21L;
    public static final long DW_TAG_BASE_TYPE = 0x24L;
    public static final long DW_TAG_CONST_TYPE = 0x26L;
    public static final long DW_TAG_ENUMERATOR = 0x28L;
    public static final long DW_TAG_VOLATILE_TYPE = 0x35L;
    public static final long DW_TAG_RESTRICT_TYPE = 0x37L;
    public static final long DW_TAG_UNSPECIFIED_TYPE = 0x3bL;
    public static final long DW_TAG_RVALUE_REFERENCE_TYPE = 0x42L;
    public static final long DW_TAG_ATOMIC_TYPE = 0x47L;
    public static final long DW_TAG_VARIABLE = 0x34L;

    public static final short DW_AT_BYTE_SIZE = 0x0b;
    public static final short DW_AT_LOCATION = 0x02;
    public static final short DW_AT_BIT_SIZE = 0x0d;
    public static final short DW_AT_LOW_PC = 0x11;
    public static final short DW_AT_HIGH_PC = 0x12;
    public static final short DW_AT_LANGUAGE = 0x13;
    public static final short DW_AT_STMT_LIST = 0x10;
    public static final short DW_AT_RANGES = 0x55;
    public static final short DW_AT_CONST_VALUE = 0x1c;
    public static final short DW_AT_PROTOTYPED = 0x27;
    public static final short DW_AT_ARTIFICIAL = 0x34;
    public static final short DW_AT_CALLING_CONVENTION = 0x36;
    public static final short DW_AT_COUNT = 0x37;
    public static final short DW_AT_DATA_MEMBER_LOCATION = 0x38;
    public static final short DW_AT_DECL_FILE = 0x3a;
    public static final short DW_AT_DECL_LINE = 0x3b;
    public static final short DW_AT_DECLARATION = 0x3c;
    public static final short DW_AT_ENCODING = 0x3e;
    public static final short DW_AT_EXTERNAL = 0x3f;
    public static final short DW_AT_TYPE = 0x49;
    public static final short DW_AT_DATA_BIT_OFFSET = 0x6b;
    public static final short DW_AT_NORETURN = (short) 0x87;

    public static final long DW_ATE_ADDRESS = 0x01L;
    public static final long DW_ATE_BOOLEAN = 0x02L;
    public static final long DW_ATE_FLOAT = 0x04L;
    public static final long DW_ATE_SIGNED = 0x05L;
    public static final long DW_ATE_SIGNED_CHAR = 0x06L;
    public static final long DW_ATE_UNSIGNED = 0x07L;
    public static final long DW_ATE_UNSIGNED_CHAR = 0x08L;
    public static final long DW_ATE_UTF = 0x10L;
    public static final long DW_CC_NORMAL = 0x01L;

    public static final long DW_LANG_C11 = 0x001dL;
    public static final int DWARF_DRD_BUFFER_VERSION = 2;
}
