/*  LibDwarf.java
 *
 */

import com.sun.jna.*;
import com.sun.jna.ptr.*;

/* ------------------------------------------------------------------------- */
/*  Shared DWARF constants                                                   */
/* ------------------------------------------------------------------------- */

/* ------------------------------------------------------------------------- */
/* 1. READER / CONSUMER interface */
/* ------------------------------------------------------------------------- */
public interface LibDwarf extends Library {

    /* load the reader library */
    LibDwarf C = Native.load(
            Platform.isWindows() ? "libdwarf" : "dwarf",
            LibDwarf.class);

    /* -------- opaque handles -------- */
    final class Dwarf_Debug extends PointerType {
        public Dwarf_Debug() {
        }

        public Dwarf_Debug(Pointer p) {
            super(p);
        }
    }

    final class Dwarf_Error extends PointerType {
        public Dwarf_Error() {
        }

        public Dwarf_Error(Pointer p) {
            super(p);
        }
    }

    /* -------- core consumer calls (subset) -------- */
    int dwarf_init(int fd, int access,
            Pointer errhand, Pointer errarg,
            PointerByReference dbg /* out */,
            PointerByReference error);

    int dwarf_finish(Dwarf_Debug dbg, PointerByReference error);

    int dwarf_next_cu_header_d(Dwarf_Debug dbg,
            LongByReference cu_header_length,
            ShortByReference version_stamp,
            LongByReference abbr_offset,
            ShortByReference addr_size,
            LongByReference next_cu_header_offset,
            ShortByReference header_cu_type,
            PointerByReference error);

    /* -------- error helpers -------- */
    String dwarf_errmsg(Dwarf_Error err);

    long dwarf_errno(Dwarf_Error err);
}
