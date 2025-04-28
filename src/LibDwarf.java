import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Platform;
import com.sun.jna.Pointer;
import com.sun.jna.PointerType;
import com.sun.jna.ptr.LongByReference;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.ptr.ShortByReference;

/**
 * Minimal JNA mapping for the libdwarf shared library (v0.12.0).
 * <p>
 * • Only the handful of entry‑points most Java tools need are mapped here.
 * • Add more methods/structs as required – just follow the existing pattern.
 * • The native library is expected on the Java library path (see
 * resources/linux-x86-64 & win32-x86-64).
 */
public interface LibDwarf extends Library {

    /*
     * ---------------------------------------------------------------------
     * Loading
     * ------------------------------------------------------------------
     */
    LibDwarf INSTANCE = Native.load(Platform.isWindows() ? "libdwarf" : "dwarf",
            LibDwarf.class);

    /*
     * ---------------------------------------------------------------------
     * Simple typedef helpers
     * ------------------------------------------------------------------
     */
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

    /*
     * ---------------------------------------------------------------------
     * Constants (trimmed)
     * ------------------------------------------------------------------
     */
    int DW_DLC_READ = 0x0001; // read‑only access
    int DW_DLC_WRITE = 0x0002; // write access (for DWARF generators)

    /*
     * ---------------------------------------------------------------------
     * Core API – just a starter set
     * ------------------------------------------------------------------
     */

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
