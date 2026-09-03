package ghidradwarfforge.nativeapi;

import com.sun.jna.Library;

import ghidradwarfforge.nativeapi.DwarfNativeTypes.Error;

/** Minimal consumer API used to identify the native and decode producer errors. */
public interface LibDwarfConsumer extends Library {
    // libdwarf.h 2.3.2: const char *dwarf_package_version(void)
    String dwarf_package_version();

    // libdwarf.h 2.3.2: Dwarf_Unsigned dwarf_errno(Dwarf_Error)
    long dwarf_errno(Error error);

    // libdwarf.h 2.3.2 lines 7133-7140.
    String dwarf_errmsg_by_number(long errorNumber);

    // dwarf_errmsg(Dwarf_Error) is intentionally not mapped here: libdwarfp's
    // producer error structure contains only er_errval, while the consumer
    // structure also contains er_msg and allocation metadata.

}
