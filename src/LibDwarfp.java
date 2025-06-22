/* ===================================================================== */
/* JNA interface to libdwarfp                                           */
/* ===================================================================== */

import com.sun.jna.*;
import com.sun.jna.ptr.*;

interface LibDwarfp extends Library {

        LibDwarfp INSTANCE = Native.load(
                        Platform.isWindows() ? "libdwarfp" : "dwarfp",
                        LibDwarfp.class);

        /* ---------------------------------------------------------------- */
        /* Callback types */
        /* ---------------------------------------------------------------- */
        interface DwarfCallbackFunc extends Callback {
                int apply(
                                Pointer name, // const char*
                                int size, // int (NOT long)
                                NativeLong type, // Dwarf_Unsigned
                                NativeLong flags,
                                NativeLong link,
                                NativeLong info,
                                NativeLongByReference sectIdxOut, // Dwarf_Unsigned*
                                Pointer userData,
                                IntByReference errOut); // int*
        }

        interface Dwarf_Error_Handler extends Callback {
                void invoke(int errorNo, Pointer errArg);
        }

        /* ---------------------------------------------------------------- */
        /* opaque handles */
        /* ---------------------------------------------------------------- */
        class Dwarf_P_Debug extends PointerType {
                public Dwarf_P_Debug() {
                }

                public Dwarf_P_Debug(Pointer p) {
                        super(p);
                }
        }

        class Dwarf_P_Die extends PointerType {
                public Dwarf_P_Die() {
                }

                public Dwarf_P_Die(Pointer p) {
                        super(p);
                }
        }

        /* ---------------------------------------------------------------- */
        /* producer entry / exit */
        /* ---------------------------------------------------------------- */
        int dwarf_producer_init(long flags,
                        DwarfCallbackFunc cb,
                        Dwarf_Error_Handler eh,
                        Pointer errarg,
                        Pointer userData,
                        String isaName,
                        String dwarfVersion,
                        String extra,
                        PointerByReference dbgOut,
                        PointerByReference errOut);

        int dwarf_producer_finish_a(
                        Dwarf_P_Debug dbg,
                        PointerByReference error);

        void dwarf_dealloc(Pointer dbgOrNull, Pointer ptr, int type);

        /* ---------------------------------------------------------------- */
        /* DIE helpers */
        /* ---------------------------------------------------------------- */
        int dwarf_new_die_a(
                        Dwarf_P_Debug dbg,
                        NativeLong tag,
                        Dwarf_P_Die parent,
                        Dwarf_P_Die child,
                        Dwarf_P_Die left,
                        Dwarf_P_Die right,
                        PointerByReference die_out,
                        PointerByReference err);

        long dwarf_dieoffset(Dwarf_P_Die die);

        int dwarf_add_AT_name_a(
                        Dwarf_P_Die die,
                        String name,
                        PointerByReference attrOut,
                        PointerByReference err);

        int dwarf_add_AT_producer_a(
                        Dwarf_P_Die die,
                        String producer,
                        PointerByReference attrOut,
                        PointerByReference err);

        int dwarf_add_AT_unsigned_const_a(
                        Dwarf_P_Debug dbg,
                        Dwarf_P_Die die,
                        short attr,
                        long value,
                        PointerByReference attrOut,
                        PointerByReference err);

        int dwarf_add_arange_c(
                        Dwarf_P_Debug dbg,
                        long address,
                        long length,
                        long symbolIndex,
                        long offsetFromSymbolIndex,
                        long cuDieOffset,
                        PointerByReference error);

        /* --- NEW: explicit tree / debug attachment ---------------------- */
        int dwarf_die_link_a(
                        Dwarf_P_Die die,
                        Dwarf_P_Die parent,
                        Dwarf_P_Die child,
                        Dwarf_P_Die leftSibling,
                        Dwarf_P_Die rightSibling,
                        PointerByReference error);

        int dwarf_add_die_to_debug_a(
                        Dwarf_P_Debug dbg,
                        Dwarf_P_Die die,
                        PointerByReference error);

        int dwarf_add_AT_const_value_string_a(
                        Dwarf_P_Die die,
                        String value,
                        PointerByReference attrOut,
                        PointerByReference err);

        int dwarf_transform_to_disk_form_a(LibDwarfp.Dwarf_P_Debug dbg,
                        PointerByReference err);

        int dwarf_get_section_bytes_a(Dwarf_P_Debug dbg,
                        int dwSectKind,
                        NativeLongByReference elfIndexOut,
                        NativeLongByReference lengthOut,
                        PointerByReference dataOut,
                        PointerByReference errOut);
        
        int dwarf_add_AT_targ_address_c(
                Dwarf_P_Debug dbg,        /* producer handle               */
                Dwarf_P_Die   die,        /* the DIE you add to            */
                short         attr,       /* e.g. DW_AT_low_pc             */
                long          symIndex,   /* 0  ? absolute value, no reloc */
                long          offset,     /* the actual address/offset     */
                PointerByReference err);

}