/* SPDX-License-Identifier: MIT. Fixed ordinary-memory values, no MMIO accesses. */
#include <stdint.h>

enum ForgeFlags {
    FORGE_NONE = 0,
    FORGE_READ = 1,
    FORGE_READ_ALIAS = 1,
    FORGE_WRITE = 2,
    FORGE_BOTH = 3,
    FORGE_HIGH = 0x80000000u
};
typedef enum ForgeFlags forge_flags_witness;
struct ForgeNode {
    unsigned int a : 3;
    unsigned int b : 5;
    int value;
    struct ForgeNode *next;
    struct ForgeNode *unreadable;
};
typedef struct ForgeNode forge_node_witness;

enum __attribute__((packed)) ForgeSigned8 { SIGNED8_ZERO = 0, SIGNED8_LOW = 1, SIGNED8_HIGH = -128 };
enum __attribute__((packed)) ForgeUnsigned16 { UNSIGNED16_ZERO = 0, UNSIGNED16_LOW = 1, UNSIGNED16_HIGH = 32768 };
enum ForgeUnsigned64 { UNSIGNED64_ZERO = 0, UNSIGNED64_LOW = 1, UNSIGNED64_HIGH = UINT64_C(0x4000000000000000) };
enum ForgeSigned64 { SIGNED64_ZERO = 0, SIGNED64_LOW = 1, SIGNED64_HIGH = INT64_MIN };
typedef enum ForgeSigned8 forge_signed8_witness;
typedef enum ForgeUnsigned16 forge_unsigned16_witness;
typedef enum ForgeUnsigned64 forge_unsigned64_witness;
typedef enum ForgeSigned64 forge_signed64_witness;

struct ForgeBranch { struct ForgeNode node; int tail; };
struct ForgeEnvelope {
    struct ForgeBranch branch;
    struct ForgeNode *nil;
    unsigned char octets[12];
};
typedef struct ForgeEnvelope forge_envelope_witness;
struct ForgeChoice { int selected; };
struct ForgeOtherChoice { long long other; };
struct ForgeAmbiguous { int member; };

forge_flags_witness forge_flags = 5;
forge_flags_witness forge_zero = 0;
forge_flags_witness forge_combined = 3;
forge_flags_witness forge_high = 0x80000001u;
forge_flags_witness forge_text = 16;
forge_node_witness forge_node = {5, 17, 42, &forge_node, (struct ForgeNode *)(uintptr_t)1};
forge_signed8_witness forge_signed8 = -127;
forge_unsigned16_witness forge_unsigned16 = 0x8005;
forge_unsigned64_witness forge_unsigned64 = UINT64_C(0xc000000000000005);
forge_signed64_witness forge_signed64 = INT64_MIN + 1;
forge_envelope_witness forge_envelope = {{{5, 17, 42, &forge_node, 0}, -9}, 0,
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}};
struct ForgeChoice forge_choice = {7};
struct ForgeOtherChoice forge_other_choice = {0x1122334455667788LL};
struct ForgeAmbiguous forge_ambiguous = {9};
struct ForgeAmbiguous forge_other_ambiguous = {11};

__attribute__((noinline)) int forge_formatter_marker(void) {
    __asm__ volatile ("" ::: "memory");
    return forge_node.value;
}
int main(void) {
    return forge_formatter_marker() != 42;
}
