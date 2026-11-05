/* Compiler reference for listing/equate/context preservation tests.
 * Listing comments and equates are applied to a private Ghidra program by the
 * integration harness; these C comments are not substitutes for that evidence.
 */
#include <stdint.h>

volatile int ANNOTATION_COLLISION = 101;
volatile int8_t annotation_s8 = -7;
volatile uint8_t annotation_u8 = UINT8_MAX;
volatile int16_t annotation_s16 = INT16_MIN;
volatile uint16_t annotation_u16 = UINT16_MAX;
volatile int32_t annotation_s32 = INT32_MIN;
volatile uint32_t annotation_u32 = UINT32_MAX;
volatile int64_t annotation_s64 = INT64_MIN;
volatile uint64_t annotation_u64 = UINT64_MAX;
volatile unsigned char annotation_data[] = {0x19, 0x23, 0x00, 0xff};

typedef struct {
    int member;
} ANNOTATION_TYPE;
volatile ANNOTATION_TYPE annotation_object = {5};

enum annotation_enum {
    ANNOTATION_ENUM_COLLISION = 3
};
volatile enum annotation_enum annotation_enum_object = ANNOTATION_ENUM_COLLISION;

__attribute__((noinline, noclone)) int annotation_probe(int input)
{
    int ANNOTATION_LOCAL = 11;
    int sum = input;
    __asm__ volatile(".globl annotation_literal_19\nannotation_literal_19:\nnop" ::: "memory");
    sum += 19;
    __asm__ volatile(".globl annotation_literal_23\nannotation_literal_23:\nnop" ::: "memory");
    sum += 23;
    __asm__ volatile(".globl annotation_live\nannotation_live:\nnop" ::: "memory");
    sum += ANNOTATION_LOCAL + ANNOTATION_COLLISION;
    __asm__ volatile(".globl annotation_gap_begin\nannotation_gap_begin:\nnop\nnop\n"
        ".globl annotation_gap_end\nannotation_gap_end:\nnop" ::: "memory");
    return sum;
}

/* Keep this local separate from the folded dynamic-equate expression above. */
__attribute__((noinline, noclone)) int annotation_conflicts(int input)
{
    int ANNOTATION_LOCAL = 11;
    __asm__ volatile(".globl annotation_conflict_live\nannotation_conflict_live:\nnop" ::: "memory");
    return input + ANNOTATION_LOCAL;
}

/* A genuine native decompiler instruction-budget failure can target this body.
 * Calling it still succeeds in the unmodified compiler reference.
 */
__attribute__((noinline, noclone)) int annotation_failure(int input)
{
    volatile int sum = input;
    for (int index = 0; index < 5; index++) {
        sum += index;
    }
    return sum;
}

int main(void)
{
    return annotation_probe(7) != 161 || annotation_conflicts(7) != 18 ||
        annotation_failure(5) != 15 ||
        ANNOTATION_COLLISION != 101 || annotation_object.member != 5 ||
        annotation_enum_object != ANNOTATION_ENUM_COLLISION;
}
