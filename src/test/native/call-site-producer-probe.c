/* Public-API admission probe for issue #117. Not an ELF/GDB acceptance test. */
#include <stdio.h>
#include <string.h>

#include "dwarf.h"
#include "libdwarf.h"
#include "libdwarfp.h"

static int create_section(const char *name, int size, Dwarf_Unsigned type,
    Dwarf_Unsigned flags, Dwarf_Unsigned link, Dwarf_Unsigned info,
    Dwarf_Unsigned *symbol, void *user, int *error)
{
    unsigned *count = user;
    (void)name;
    (void)size;
    (void)type;
    (void)flags;
    (void)link;
    (void)info;
    if (*count >= 32) {
        *error = 1;
        return -1;
    }
    ++*count;
    *symbol = 100 + *count;
    return (int)*count;
}

int main(int argc, char **argv)
{
    const char *modes[] = {"control", "call-pc", "return-pc", "origin",
        "parameter", "value"};
    unsigned mode = 0;
    unsigned sections = 0;
    int failed = 0;
    Dwarf_P_Debug debug = NULL;
    Dwarf_Error error = NULL;
    Dwarf_P_Die unit = NULL, caller = NULL, callee = NULL, type = NULL;
    Dwarf_P_Die formal = NULL, site = NULL, parameter = NULL;
    Dwarf_P_Attribute attribute = NULL;
    Dwarf_P_Expr expression = NULL;
    Dwarf_Unsigned count = 0, next = 0;

    if (argc == 2) {
        for (mode = 0; mode < sizeof(modes) / sizeof(modes[0]); ++mode) {
            if (!strcmp(argv[1], modes[mode])) break;
        }
    }
    if (argc != 2 || mode == sizeof(modes) / sizeof(modes[0])) {
        fprintf(stderr, "usage: %s control|call-pc|return-pc|origin|parameter|value\n",
            argv[0]);
        return 2;
    }

#define CHECK(call) do { \
    int result = (call); \
    if (result != DW_DLV_OK || error != NULL) { \
        fprintf(stderr, "%s: %s: return=%d error=%s\n", modes[mode], #call, \
            result, error ? dwarf_errmsg_by_number(dwarf_errno(error)) : "none"); \
        failed = 1; \
        goto finish; \
    } \
} while (0)

    CHECK(dwarf_producer_init(DW_DLC_POINTER64 | DW_DLC_OFFSET32 |
        DW_DLC_SYMBOLIC_RELOCATIONS | DW_DLC_TARGET_LITTLEENDIAN,
        create_section, NULL, NULL, &sections, "x86_64", "V5", "",
        &debug, &error));
    CHECK(dwarf_new_die_a(debug, DW_TAG_compile_unit, NULL, NULL, NULL, NULL,
        &unit, &error));
    CHECK(dwarf_new_die_a(debug, DW_TAG_base_type, unit, NULL, NULL, NULL,
        &type, &error));
    CHECK(dwarf_add_AT_name_a(type, "int", &attribute, &error));
    CHECK(dwarf_add_AT_unsigned_const_a(debug, type, DW_AT_byte_size, 4,
        &attribute, &error));
    CHECK(dwarf_add_AT_unsigned_const_a(debug, type, DW_AT_encoding, DW_ATE_signed,
        &attribute, &error));
    CHECK(dwarf_new_die_a(debug, DW_TAG_subprogram, unit, NULL, NULL, NULL,
        &caller, &error));
    CHECK(dwarf_new_die_a(debug, DW_TAG_subprogram, unit, NULL, NULL, NULL,
        &callee, &error));
    CHECK(dwarf_new_die_a(debug, DW_TAG_formal_parameter, callee, NULL, NULL, NULL,
        &formal, &error));
    CHECK(dwarf_new_die_a(debug, DW_TAG_call_site, caller, NULL, NULL, NULL,
        &site, &error));
    CHECK(dwarf_new_die_a(debug, DW_TAG_call_site_parameter, site, NULL, NULL, NULL,
        &parameter, &error));

    switch (mode) {
    case 0:
        CHECK(dwarf_add_AT_targ_address_c(debug, caller, DW_AT_low_pc,
            0x1000, 1, &attribute, &error));
        CHECK(dwarf_add_AT_reference_c(debug, formal, DW_AT_type,
            type, &attribute, &error));
        CHECK(dwarf_new_expr_a(debug, &expression, &error));
        CHECK(dwarf_add_expr_gen_a(expression, DW_OP_reg0, 0, 0, &next, &error));
        CHECK(dwarf_add_AT_location_expr_a(debug, parameter, DW_AT_location,
            expression, &attribute, &error));
        break;
    case 1:
    case 2:
        CHECK(dwarf_add_AT_targ_address_c(debug, site,
            mode == 1 ? DW_AT_call_pc : DW_AT_call_return_pc,
            0x1000, 1, &attribute, &error));
        break;
    case 3:
    case 4:
        CHECK(dwarf_add_AT_reference_c(debug, mode == 3 ? site : parameter,
            mode == 3 ? DW_AT_call_origin : DW_AT_call_parameter,
            mode == 3 ? callee : formal, &attribute, &error));
        break;
    case 5:
        CHECK(dwarf_new_expr_a(debug, &expression, &error));
        CHECK(dwarf_add_expr_gen_a(expression, DW_OP_lit5, 0, 0, &next, &error));
        CHECK(dwarf_add_AT_location_expr_a(debug, parameter, DW_AT_call_value,
            expression, &attribute, &error));
        break;
    }
    CHECK(dwarf_add_die_to_debug_a(debug, unit, &error));
    CHECK(dwarf_transform_to_disk_form_a(debug, &count, &error));
    if (count == 0) {
        fprintf(stderr, "%s: producer returned no section buffers\n", modes[mode]);
        failed = 1;
        goto finish;
    }
    for (Dwarf_Unsigned index = 0; index < count; ++index) {
        Dwarf_Unsigned section = 0, length = 0;
        Dwarf_Ptr bytes = NULL;
        CHECK(dwarf_get_section_bytes_a(debug, index, &section, &length, &bytes,
            &error));
        if (!section || section > sections || !length || !bytes) {
            fprintf(stderr, "%s: invalid section buffer\n", modes[mode]);
            failed = 1;
            goto finish;
        }
    }
finish:
    if (debug != NULL) {
        Dwarf_Error finish_error = NULL;
        int result = dwarf_producer_finish_a(debug, &finish_error);
        if (result != DW_DLV_OK || finish_error != NULL) {
            /* Do not dereference producer-owned errors after finish. */
            fprintf(stderr, "%s: producer finish failed: return=%d\n",
                modes[mode], result);
            failed = 1;
        }
    }
    if (!failed) printf("%s: API admission and serialization passed\n", modes[mode]);
    return failed ? 1 : 0;
#undef CHECK
}
