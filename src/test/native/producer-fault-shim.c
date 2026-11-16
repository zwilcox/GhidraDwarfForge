/* Test-only Linux forwarding shim. Never package this as a production native.
 * Declarations come from the pinned release headers; unchanged calls reach the
 * actual producer. Each configured fault fires once, before Java consumes it.
 */
#include <dlfcn.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libdwarf.h"
#include "libdwarfp.h"

_Static_assert(sizeof(Dwarf_Unsigned) == 8, "fixed-width producer unsigned");
_Static_assert(sizeof(Dwarf_Signed) == 8, "fixed-width producer signed");
_Static_assert(sizeof(int) == 4, "producer status/version width");

static void *library;
static char mode[80];
static unsigned long long starts, finishes, finish_attempts, faults;
static int fired;
static Dwarf_Callback_Func callback;
static Dwarf_Unsigned string_section;
static struct Dwarf_Relocation_Data_s *relocation_copy;

static void *symbol(const char *name) {
    if (!library) library = dlopen(FORGE_REAL_PRODUCER, RTLD_NOW | RTLD_LOCAL);
    void *result = library ? dlsym(library, name) : NULL;
    if (!result) {
        fprintf(stderr, "fault shim cannot resolve %s: %s\n", name, dlerror());
        abort();
    }
    return result;
}

static int hit(const char *name) {
    if (fired || strcmp(mode, name)) return 0;
    fired = 1;
    faults++;
    return 1;
}

void forge_test_mode(const char *selected) {
    if (!selected || strlen(selected) >= sizeof(mode) || starts != finishes) abort();
    strcpy(mode, selected);
    fired = 0;
}

unsigned long long forge_test_starts(void) { return starts; }
unsigned long long forge_test_finishes(void) { return finishes; }
unsigned long long forge_test_finish_attempts(void) { return finish_attempts; }
unsigned long long forge_test_faults(void) { return faults; }

static int section_callback(const char *name, int size, Dwarf_Unsigned type,
        Dwarf_Unsigned flags, Dwarf_Unsigned link, Dwarf_Unsigned info,
        Dwarf_Unsigned *section_symbol, void *user, int *error) {
    const char *reported = name;
    if (!strcmp(name, ".debug_abbrev") && hit("duplicate-section")) reported = ".debug_str";
    int index = callback(reported, size, type, flags, link, info, section_symbol, user, error);
    if (!strcmp(name, ".debug_str")) string_section = (Dwarf_Unsigned)index;
    return index;
}

int dwarf_producer_init(Dwarf_Unsigned flags, Dwarf_Callback_Func function,
        Dwarf_Handler handler, Dwarf_Ptr argument, void *user, const char *isa,
        const char *version, const char *extra, Dwarf_P_Debug *debug, Dwarf_Error *error) {
    typedef int (*Function)(Dwarf_Unsigned, Dwarf_Callback_Func, Dwarf_Handler,
        Dwarf_Ptr, void *, const char *, const char *, const char *, Dwarf_P_Debug *, Dwarf_Error *);
    if (hit("init-error")) { *debug = NULL; *error = NULL; return DW_DLV_ERROR; }
    if (hit("init-null")) { *debug = NULL; *error = NULL; return DW_DLV_OK; }
    callback = function;
    string_section = 0;
    int result = ((Function)symbol("dwarf_producer_init"))(flags, section_callback,
        handler, argument, user, isa, version, extra, debug, error);
    if (result == DW_DLV_OK && *debug) starts++;
    return result;
}

int dwarf_pro_set_default_string_form(Dwarf_P_Debug debug, int form, Dwarf_Error *error) {
    typedef int (*Function)(Dwarf_P_Debug, int, Dwarf_Error *);
    if (hit("string-no-entry")) { *error = NULL; return DW_DLV_NO_ENTRY; }
    /* This is a real producer-generated error, not a fabricated error pointer. */
    if (hit("string-error")) form = INT_MAX;
    return ((Function)symbol("dwarf_pro_set_default_string_form"))(debug, form, error);
}

int dwarf_new_die_a(Dwarf_P_Debug debug, Dwarf_Tag tag, Dwarf_P_Die parent,
        Dwarf_P_Die child, Dwarf_P_Die left, Dwarf_P_Die right, Dwarf_P_Die *die,
        Dwarf_Error *error) {
    typedef int (*Function)(Dwarf_P_Debug, Dwarf_Tag, Dwarf_P_Die, Dwarf_P_Die,
        Dwarf_P_Die, Dwarf_P_Die, Dwarf_P_Die *, Dwarf_Error *);
    if (hit("die-null")) { *die = NULL; *error = NULL; return DW_DLV_OK; }
    return ((Function)symbol("dwarf_new_die_a"))(debug, tag, parent, child, left, right, die, error);
}

int dwarf_transform_to_disk_form_a(Dwarf_P_Debug debug, Dwarf_Unsigned *count,
        Dwarf_Error *error) {
    typedef int (*Function)(Dwarf_P_Debug, Dwarf_Unsigned *, Dwarf_Error *);
    int result = ((Function)symbol("dwarf_transform_to_disk_form_a"))(debug, count, error);
    if (result != DW_DLV_OK) return result;
    if (hit("transform-error")) { *error = NULL; return DW_DLV_ERROR; }
    if (hit("buffer-count-zero")) *count = 0;
    if (hit("buffer-count-large")) *count = 100001;
    return result;
}

int dwarf_get_section_bytes_a(Dwarf_P_Debug debug, Dwarf_Unsigned index,
        Dwarf_Unsigned *section, Dwarf_Unsigned *length, Dwarf_Ptr *data, Dwarf_Error *error) {
    typedef int (*Function)(Dwarf_P_Debug, Dwarf_Unsigned, Dwarf_Unsigned *,
        Dwarf_Unsigned *, Dwarf_Ptr *, Dwarf_Error *);
    int result = ((Function)symbol("dwarf_get_section_bytes_a"))(debug, index, section, length, data, error);
    if (result != DW_DLV_OK) return result;
    if (hit("section-error")) { *error = NULL; return DW_DLV_ERROR; }
    if (hit("section-unknown")) *section = ULLONG_MAX;
    if (hit("section-negative-length")) *length = ULLONG_MAX;
    if (hit("section-large-length")) *length = (Dwarf_Unsigned)INT_MAX + 1;
    if (hit("section-null")) *data = NULL;
    if (*section == string_section && hit("missing-strings")) *length = 0;
    return result;
}

int dwarf_get_relocation_info_count(Dwarf_P_Debug debug, Dwarf_Unsigned *count,
        int *version, Dwarf_Error *error) {
    typedef int (*Function)(Dwarf_P_Debug, Dwarf_Unsigned *, int *, Dwarf_Error *);
    int result = ((Function)symbol("dwarf_get_relocation_info_count"))(debug, count, version, error);
    if (result != DW_DLV_OK) return result;
    if (hit("relocation-version")) *version = 0;
    if (hit("relocation-no-groups")) *count = 0;
    return result;
}

int dwarf_get_relocation_info(Dwarf_P_Debug debug, Dwarf_Unsigned *section,
        Dwarf_Unsigned *target, Dwarf_Unsigned *count, Dwarf_Relocation_Data *data,
        Dwarf_Error *error) {
    typedef int (*Function)(Dwarf_P_Debug, Dwarf_Unsigned *, Dwarf_Unsigned *,
        Dwarf_Unsigned *, Dwarf_Relocation_Data *, Dwarf_Error *);
    int result = ((Function)symbol("dwarf_get_relocation_info"))(debug, section, target, count, data, error);
    if (result != DW_DLV_OK) return result;
    if (hit("relocation-section")) *section = ULLONG_MAX;
    if (hit("relocation-target")) *target = ULLONG_MAX;
    if (hit("relocation-empty")) *count = 0;
    if (hit("relocation-null")) *data = NULL;
    if (fired || !*count || !*data) return result;
    if (*count > 100000) abort();
    free(relocation_copy);
    relocation_copy = malloc((size_t)*count * sizeof(*relocation_copy));
    if (!relocation_copy) abort();
    memcpy(relocation_copy, *data, (size_t)*count * sizeof(*relocation_copy));
    /* Never corrupt the real producer's allocation or cleanup bookkeeping. */
    *data = relocation_copy;
    if (hit("relocation-offset-negative")) relocation_copy[0].drd_offset = ULLONG_MAX;
    if (hit("relocation-offset-outside")) relocation_copy[0].drd_offset = INT_MAX;
    if (hit("relocation-zero-width")) relocation_copy[0].drd_length = 0;
    if (hit("relocation-unknown-symbol")) relocation_copy[0].drd_symbol_index = ULLONG_MAX;
    for (Dwarf_Unsigned i = 0; i < *count; i++) {
        if (relocation_copy[i].drd_symbol_index == 0x1001) {
            if (hit("relocation-address-width")) relocation_copy[i].drd_length = 4;
            if (hit("relocation-missing-address")) relocation_copy[i].drd_symbol_index = 1;
        }
    }
    return result;
}

int dwarf_producer_finish_a(Dwarf_P_Debug debug, Dwarf_Error *error) {
    typedef int (*Function)(Dwarf_P_Debug, Dwarf_Error *);
    finish_attempts++;
    /* Failure precedes release. The exporter must still attempt cleanup. */
    if (hit("finish-error")) { *error = NULL; return DW_DLV_ERROR; }
    int result = ((Function)symbol("dwarf_producer_finish_a"))(debug, error);
    if (result == DW_DLV_OK) finishes++;
    free(relocation_copy);
    relocation_copy = NULL;
    return result;
}
