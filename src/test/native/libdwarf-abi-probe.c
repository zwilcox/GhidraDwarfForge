#include <stddef.h>
#include <stdio.h>

#include "libdwarf.h"
#include "libdwarfp.h"

#define ASSERT_FUNCTION(name, signature) \
    _Static_assert(__builtin_types_compatible_p(__typeof__(&(name)), signature), \
        "ABI signature mismatch: " #name)

typedef int (*ProducerInit)(Dwarf_Unsigned, Dwarf_Callback_Func, Dwarf_Handler,
    Dwarf_Ptr, void *, const char *, const char *, const char *, Dwarf_P_Debug *,
    Dwarf_Error *);
typedef int (*SetStringForm)(Dwarf_P_Debug, int, Dwarf_Error *);
typedef int (*NewDie)(Dwarf_P_Debug, Dwarf_Tag, Dwarf_P_Die, Dwarf_P_Die,
    Dwarf_P_Die, Dwarf_P_Die, Dwarf_P_Die *, Dwarf_Error *);
typedef int (*AddDie)(Dwarf_P_Debug, Dwarf_P_Die, Dwarf_Error *);
typedef int (*LinkDie)(Dwarf_P_Die, Dwarf_P_Die, Dwarf_P_Die, Dwarf_P_Die,
    Dwarf_P_Die, Dwarf_Error *);
typedef int (*AddName)(Dwarf_P_Die, char *, Dwarf_P_Attribute *, Dwarf_Error *);
typedef int (*AddProducer)(Dwarf_P_Die, char *, Dwarf_P_Attribute *, Dwarf_Error *);
typedef int (*AddUnsigned)(Dwarf_P_Debug, Dwarf_P_Die, Dwarf_Half,
    Dwarf_Unsigned, Dwarf_P_Attribute *, Dwarf_Error *);
typedef int (*AddReference)(Dwarf_P_Debug, Dwarf_P_Die, Dwarf_Half,
    Dwarf_P_Die, Dwarf_P_Attribute *, Dwarf_Error *);
typedef int (*AddSleb)(Dwarf_P_Die, Dwarf_Half, Dwarf_Signed,
    Dwarf_P_Attribute *, Dwarf_Error *);
typedef int (*AddUleb)(Dwarf_P_Die, Dwarf_Half, Dwarf_Unsigned,
    Dwarf_P_Attribute *, Dwarf_Error *);
typedef int (*AddDataref)(Dwarf_P_Debug, Dwarf_P_Die, Dwarf_Half,
    Dwarf_Unsigned, Dwarf_Unsigned, Dwarf_P_Attribute *, Dwarf_Error *);
typedef int (*AddAddress)(Dwarf_P_Debug, Dwarf_P_Die, Dwarf_Half,
    Dwarf_Unsigned, Dwarf_Unsigned, Dwarf_P_Attribute *, Dwarf_Error *);
typedef int (*AddFlag)(Dwarf_P_Debug, Dwarf_P_Die, Dwarf_Half, Dwarf_Small,
    Dwarf_P_Attribute *, Dwarf_Error *);
typedef int (*NewExpression)(Dwarf_P_Debug, Dwarf_P_Expr *, Dwarf_Error *);
typedef int (*AddExpressionOperation)(Dwarf_P_Expr, Dwarf_Small,
    Dwarf_Unsigned, Dwarf_Unsigned, Dwarf_Unsigned *, Dwarf_Error *);
typedef int (*AddExpressionAddress)(Dwarf_P_Expr, Dwarf_Unsigned,
    Dwarf_Unsigned, Dwarf_Unsigned *, Dwarf_Error *);
typedef int (*AddLocationExpression)(Dwarf_P_Debug, Dwarf_P_Die, Dwarf_Half,
    Dwarf_P_Expr, Dwarf_P_Attribute *, Dwarf_Error *);
typedef int (*Transform)(Dwarf_P_Debug, Dwarf_Unsigned *, Dwarf_Error *);
typedef int (*GetSectionBytes)(Dwarf_P_Debug, Dwarf_Unsigned, Dwarf_Unsigned *,
    Dwarf_Unsigned *, Dwarf_Ptr *, Dwarf_Error *);
typedef int (*GetRelocationCount)(Dwarf_P_Debug, Dwarf_Unsigned *, int *,
    Dwarf_Error *);
typedef int (*GetRelocations)(Dwarf_P_Debug, Dwarf_Unsigned *, Dwarf_Unsigned *,
    Dwarf_Unsigned *, Dwarf_Relocation_Data *, Dwarf_Error *);
typedef int (*ProducerFinish)(Dwarf_P_Debug, Dwarf_Error *);
typedef const char *(*PackageVersion)(void);
typedef Dwarf_Unsigned (*ErrorNumber)(Dwarf_Error);
typedef char *(*ErrorMessageByNumber)(Dwarf_Unsigned);

ASSERT_FUNCTION(dwarf_producer_init, ProducerInit);
ASSERT_FUNCTION(dwarf_pro_set_default_string_form, SetStringForm);
ASSERT_FUNCTION(dwarf_new_die_a, NewDie);
ASSERT_FUNCTION(dwarf_add_die_to_debug_a, AddDie);
ASSERT_FUNCTION(dwarf_die_link_a, LinkDie);
ASSERT_FUNCTION(dwarf_add_AT_name_a, AddName);
ASSERT_FUNCTION(dwarf_add_AT_producer_a, AddProducer);
ASSERT_FUNCTION(dwarf_add_AT_unsigned_const_a, AddUnsigned);
ASSERT_FUNCTION(dwarf_add_AT_reference_c, AddReference);
ASSERT_FUNCTION(dwarf_add_AT_any_value_sleb_a, AddSleb);
ASSERT_FUNCTION(dwarf_add_AT_any_value_uleb_a, AddUleb);
ASSERT_FUNCTION(dwarf_add_AT_dataref_a, AddDataref);
ASSERT_FUNCTION(dwarf_add_AT_targ_address_c, AddAddress);
ASSERT_FUNCTION(dwarf_add_AT_flag_a, AddFlag);
ASSERT_FUNCTION(dwarf_new_expr_a, NewExpression);
ASSERT_FUNCTION(dwarf_add_expr_gen_a, AddExpressionOperation);
ASSERT_FUNCTION(dwarf_add_expr_addr_c, AddExpressionAddress);
ASSERT_FUNCTION(dwarf_add_AT_location_expr_a, AddLocationExpression);
ASSERT_FUNCTION(dwarf_transform_to_disk_form_a, Transform);
ASSERT_FUNCTION(dwarf_get_section_bytes_a, GetSectionBytes);
ASSERT_FUNCTION(dwarf_get_relocation_info_count, GetRelocationCount);
ASSERT_FUNCTION(dwarf_get_relocation_info, GetRelocations);
ASSERT_FUNCTION(dwarf_producer_finish_a, ProducerFinish);
ASSERT_FUNCTION(dwarf_package_version, PackageVersion);
ASSERT_FUNCTION(dwarf_errno, ErrorNumber);
ASSERT_FUNCTION(dwarf_errmsg_by_number, ErrorMessageByNumber);

_Static_assert(sizeof(Dwarf_Unsigned) == 8, "Dwarf_Unsigned must be 64-bit");
_Static_assert(sizeof(Dwarf_Signed) == 8, "Dwarf_Signed must be 64-bit");
_Static_assert(sizeof(Dwarf_Off) == 8, "Dwarf_Off must be 64-bit");
_Static_assert(sizeof(Dwarf_Addr) == 8, "Dwarf_Addr must be 64-bit");
_Static_assert(sizeof(Dwarf_Half) == 2, "Dwarf_Half must be 16-bit");
_Static_assert(sizeof(Dwarf_Small) == 1, "Dwarf_Small must be 8-bit");
_Static_assert(sizeof(struct Dwarf_Relocation_Data_s) == 24,
    "Dwarf_Relocation_Data must match the JNA structure size");
_Static_assert(offsetof(struct Dwarf_Relocation_Data_s, drd_offset) == 8,
    "Dwarf_Relocation_Data offset field must start at byte 8");
_Static_assert(offsetof(struct Dwarf_Relocation_Data_s, drd_symbol_index) == 16,
    "Dwarf_Relocation_Data symbol field must start at byte 16");

int main(void)
{
    printf("libdwarf-abi-probe=PASS unsigned=%zu signed=%zu off=%zu addr=%zu "
        "half=%zu small=%zu pointer=%zu relocation=%zu\n",
        sizeof(Dwarf_Unsigned), sizeof(Dwarf_Signed), sizeof(Dwarf_Off),
        sizeof(Dwarf_Addr), sizeof(Dwarf_Half), sizeof(Dwarf_Small),
        sizeof(void *), sizeof(struct Dwarf_Relocation_Data_s));
    return 0;
}
