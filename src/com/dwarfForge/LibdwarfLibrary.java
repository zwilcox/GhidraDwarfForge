package com.zwilcox.dwarfForge;

import com.sun.jna.*;
import com.sun.jna.ptr.*;

/**
 * JNA bindings for <b>libdwarf v0.12.0</b> produced by our GitHub workflow.
 * <p>
 * The workflow places the native binaries under
 * <pre>
 *   libdwarf/linux/   libdwarf.a  dwarfdump        (and optionally libdwarf.so)
 *   libdwarf/windows/ libdwarf.dll libdwarf.a dwarfdump.exe
 * </pre>
 * This interface adds that directory to JNA’s search path at runtime so you can
 * run tests straight from a checkout without installing the library system‑wide.
 * </p>
 */
public interface LibdwarfLibrary extends Library {

    /* ------------------------------------------------------------------
     *  Library loading
     * ------------------------------------------------------------------ */
    /** Basename for the shared library (JNA adds platform prefix/suffix). */
    String LIB_BASE = Platform.isWindows() ? "libdwarf" : "dwarf";

    /* Dynamically add our repo’s libdwarf/{linux|windows} directory */
    static {
        String repoRoot = System.getProperty("user.dir");
        String defaultDir = repoRoot + "/libdwarf/" + (Platform.isWindows() ? "windows" : "linux");
        // Allow override via -Dlibdwarf.path=/abs/dir
        String configuredDir = System.getProperty("libdwarf.path", defaultDir);
        NativeLibrary.addSearchPath(LIB_BASE, configuredDir);
    }

    /** Singleton instance – loads the native shared object */
    LibdwarfLibrary INSTANCE = Native.load(LIB_BASE, LibdwarfLibrary.class);

    /* ------------------------------------------------------------------
     *  Return codes & constants
     * ------------------------------------------------------------------ */
    int DW_DLV_ERROR    = -1;
    int DW_DLV_NO_ENTRY = 0;
    int DW_DLV_OK       = 1;

    int DW_GROUPNUMBER_ANY  = 0;
    int DW_GROUPNUMBER_BASE = 1;
    int DW_GROUPNUMBER_DWO  = 2;

    /* ------------------------------------------------------------------
     *  Opaque handles
     * ------------------------------------------------------------------ */
    class Dwarf_Debug      extends PointerType {}
    class Dwarf_Die        extends PointerType {}
    class Dwarf_Attribute  extends PointerType {}
    class Dwarf_Error      extends PointerType {}
    class Dwarf_Line       extends PointerType {}

    class Dwarf_DebugByRef     extends ByReference { public Dwarf_DebugByRef() { super(Native.POINTER_SIZE); } }
    class Dwarf_DieByRef       extends ByReference { public Dwarf_DieByRef() { super(Native.POINTER_SIZE); } }
    class Dwarf_AttributeByRef extends ByReference { public Dwarf_AttributeByRef() { super(Native.POINTER_SIZE); } }
    class Dwarf_ErrorByRef     extends ByReference { public Dwarf_ErrorByRef() { super(Native.POINTER_SIZE); } }
    class Dwarf_LineByRef      extends ByReference { public Dwarf_LineByRef() { super(Native.POINTER_SIZE); } }

    /* ------------------------------------------------------------------
     *  Error helpers
     * ------------------------------------------------------------------ */
    String dwarf_errmsg(Dwarf_Error err);
    long   dwarf_errno (Dwarf_Error err);

    /* ------------------------------------------------------------------
     *  Initialization / finish
     * ------------------------------------------------------------------ */
    int dwarf_init_path(String path,
                        Pointer dw_prefix,
                        Pointer dw_group_map,
                        int     dw_groupnum,
                        int     dw_flags,
                        Pointer errhand,
                        Dwarf_DebugByRef dbg);

    int dwarf_finish(Dwarf_Debug dbg);

    /* ------------------------------------------------------------------
     *  DIE traversal subset
     * ------------------------------------------------------------------ */
    int dwarf_siblingof_b(Dwarf_Debug dbg, Dwarf_Die die,
                          Dwarf_DieByRef sibling, Dwarf_ErrorByRef err);

    int dwarf_child(Dwarf_Die die, Dwarf_DieByRef child, Dwarf_ErrorByRef err);

    int dwarf_tag(Dwarf_Die die, ShortByReference tag, Dwarf_ErrorByRef err);

    int dwarf_diename(Dwarf_Die die, PointerByReference name, Dwarf_ErrorByRef err);

    /* ------------------------------------------------------------------
     *  Attributes subset
     * ------------------------------------------------------------------ */
    int dwarf_attr(Dwarf_Die die, int attrNum,
                   Dwarf_AttributeByRef attr, Dwarf_ErrorByRef err);

    int dwarf_formudata(Dwarf_Attribute attr, LongByReference val, Dwarf_ErrorByRef err);

    int dwarf_formstring(Dwarf_Attribute attr, PointerByReference strPtr, Dwarf_ErrorByRef err);

    /* ------------------------------------------------------------------
     *  Line table subset
     * ------------------------------------------------------------------ */
    int dwarf_srclines(Dwarf_Die cuDie, PointerByReference lines,
                       LongByReference lineCount, Dwarf_ErrorByRef err);

    int dwarf_lineno(Dwarf_Line line, IntByReference lineno, Dwarf_ErrorByRef err);

    int dwarf_lineaddr(Dwarf_Line line, LongByReference addr, Dwarf_ErrorByRef err);

    /* ------------------------------------------------------------------
     *  Convenience utility
     * ------------------------------------------------------------------ */
    static String cString(Pointer p) { return p == null ? null : p.getString(0); }
}
