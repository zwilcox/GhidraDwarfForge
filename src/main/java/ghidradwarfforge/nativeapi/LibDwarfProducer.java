package ghidradwarfforge.nativeapi;

import com.sun.jna.Callback;
import com.sun.jna.Library;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.LongByReference;
import com.sun.jna.ptr.PointerByReference;

import ghidradwarfforge.nativeapi.DwarfNativeTypes.Debug;
import ghidradwarfforge.nativeapi.DwarfNativeTypes.Die;
import ghidradwarfforge.nativeapi.DwarfNativeTypes.Error;
import ghidradwarfforge.nativeapi.DwarfNativeTypes.Expr;

/**
 * Small, audited subset of the libdwarf 2.3.2 producer ABI.
 *
 * <p>There is deliberately no static {@code INSTANCE}: merely loading this
 * class must never load native code into the Ghidra JVM.</p>
 */
public interface LibDwarfProducer extends Library {
    /** libdwarfp.h 2.3.2 {@code Dwarf_Callback_Func}. */
    interface SectionCallback extends Callback {
        int invoke(String name, int size, long type, long flags, long link, long info,
                LongByReference sectionNameSymbolIndex, Pointer userData,
                IntByReference error);
    }

    /** libdwarf.h 2.3.2 {@code Dwarf_Handler}. */
    interface ErrorHandler extends Callback {
        void invoke(Error error, Pointer errorArgument);
    }

    // libdwarfp.h 2.3.2 lines 182-192.
    int dwarf_producer_init(long flags, SectionCallback callback, ErrorHandler errorHandler,
            Pointer errorArgument, Pointer userData, String isaName, String dwarfVersion,
            String extra, PointerByReference debugOut, PointerByReference errorOut);

    // libdwarfp.h 2.3.2 lines 194-196.
    int dwarf_pro_set_default_string_form(Debug debug, int desiredForm,
            PointerByReference errorOut);

    // libdwarfp.h 2.3.2 lines 558-566.
    int dwarf_new_die_a(Debug debug, long tag, Die parent, Die child, Die left, Die right,
            PointerByReference dieOut, PointerByReference errorOut);

    // libdwarfp.h 2.3.2 lines 569-572.
    int dwarf_add_die_to_debug_a(Debug debug, Die die, PointerByReference errorOut);

    // libdwarfp.h 2.3.2 lines 584-590.
    int dwarf_die_link_a(Die die, Die parent, Die child, Die left, Die right,
            PointerByReference errorOut);

    // libdwarfp.h 2.3.2 lines 435-438.
    int dwarf_add_AT_name_a(Die die, String name, PointerByReference attributeOut,
            PointerByReference errorOut);

    // libdwarfp.h 2.3.2 lines 378-381.
    int dwarf_add_AT_producer_a(Die die, String producer, PointerByReference attributeOut,
            PointerByReference errorOut);

    // libdwarfp.h 2.3.2 lines 300-305.
    int dwarf_add_AT_unsigned_const_a(Debug debug, Die die, short attribute, long value,
            PointerByReference attributeOut, PointerByReference errorOut);

    // libdwarfp.h 2.3.2 lines 316-321.
    int dwarf_add_AT_reference_c(Debug debug, Die die, short attribute, Die otherDie,
            PointerByReference attributeOut, PointerByReference errorOut);

    // libdwarfp.h 2.3.2 lines 401-406.
    int dwarf_add_AT_any_value_sleb_a(Die die, short attribute, long value,
            PointerByReference attributeOut, PointerByReference errorOut);

    // libdwarfp.h 2.3.2 lines 415-419.
    int dwarf_add_AT_any_value_uleb_a(Die die, short attribute, long value,
            PointerByReference attributeOut, PointerByReference errorOut);

    // libdwarfp.h 2.3.2 lines 337-344.
    int dwarf_add_AT_dataref_a(Debug debug, Die die, short attribute, long value,
            long symbolIndex, PointerByReference attributeOut,
            PointerByReference errorOut);

    // libdwarfp.h 2.3.2 lines 273-279.
    int dwarf_add_AT_targ_address_c(Debug debug, Die die, short attribute, long pcValue,
            long symbolIndex, PointerByReference attributeOut, PointerByReference errorOut);

    // libdwarfp.h 2.3.2 lines 370-375.
    int dwarf_add_AT_flag_a(Debug debug, Die die, short attribute, byte flag,
            PointerByReference attributeOut, PointerByReference errorOut);

    // libdwarfp.h 2.3.2 lines 608-611.
    int dwarf_new_expr_a(Debug debug, PointerByReference expressionOut,
            PointerByReference errorOut);

    // libdwarfp.h 2.3.2 lines 616-622.
    int dwarf_add_expr_gen_a(Expr expression, byte opcode, long operand1, long operand2,
            LongByReference nextByteOffsetOut, PointerByReference errorOut);

    // libdwarfp.h 2.3.2 lines 624-630.
    int dwarf_add_expr_addr_c(Expr expression, long address, long symbolIndex,
            LongByReference nextByteOffsetOut, PointerByReference errorOut);

    // libdwarfp.h 2.3.2 lines 354-360.
    int dwarf_add_AT_location_expr_a(Debug debug, Die die, short attribute,
            Expr expression, PointerByReference attributeOut,
            PointerByReference errorOut);

    // libdwarfp.h 2.3.2 lines 202-204.
    int dwarf_transform_to_disk_form_a(Debug debug, LongByReference bufferCountOut,
            PointerByReference errorOut);

    // libdwarfp.h 2.3.2 lines 207-212.
    int dwarf_get_section_bytes_a(Debug debug, long dwarfSection,
            LongByReference elfSectionIndexOut, LongByReference lengthOut,
            PointerByReference sectionBytesOut, PointerByReference errorOut);

    // libdwarfp.h 2.3.2 lines 214-218.
    int dwarf_get_relocation_info_count(Debug debug, LongByReference sectionCountOut,
            IntByReference bufferVersionOut, PointerByReference errorOut);

    // Dwarf_Relocation_Data is a pointer typedef, so this final output is **.
    // libdwarfp.h 2.3.2 lines 220-226.
    int dwarf_get_relocation_info(Debug debug, LongByReference elfSectionIndexOut,
            LongByReference linkedSectionIndexOut, LongByReference relocationCountOut,
            PointerByReference relocationDataOut, PointerByReference errorOut);

    // libdwarfp.h 2.3.2 lines 260-261.
    int dwarf_producer_finish_a(Debug debug, PointerByReference errorOut);
}
