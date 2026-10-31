/* Compiler-described physical carriers plus saved Ghidra logical assignments. */
#if defined(__x86_64__)
#define FIRST "r10"
#define SECOND "r11"
#define COUNTER "r8"
#define DEF32 "movl %k[value], %k[first]\n"
#define DEF64 "movq %[value], %[first]\n"
#define COPY32 "movl %k[first], %k[second]\n"
#define COPY64 "movq %[first], %[second]\n"
#define ADD32 "addl $5, %k[second]\n"
#define ADD64 "addq $5, %[second]\n"
#define RESET32 "movl $42, %k[second]\n"
#define RESET64 "movq $42, %[second]\n"
#define OLDKILL "xorl %%r10d, %%r10d\n"
#define KILL32 "movl $909, %k[second]\n"
#define KILL64 "movq $909, %[second]\n"
#define TEST "testl %k[choose], %k[choose]\n"
#define ZERO(name) "je " #name "_skipped\n"
#define JUMP(name) "jmp " #name "_join\n"
#define COUNT "movl %k[choose], %%r8d\naddl $2, %%r8d\n"
#define AGAIN(name) "subl $1, %%r8d\njnz " #name "_loop\n"
#elif defined(__aarch64__)
#define FIRST "x9"
#define SECOND "x10"
#define COUNTER "x11"
#define DEF32 "mov %w[first], %w[value]\n"
#define DEF64 "mov %x[first], %x[value]\n"
#define COPY32 "mov %w[second], %w[first]\n"
#define COPY64 "mov %x[second], %x[first]\n"
#define ADD32 "add %w[second], %w[second], #5\n"
#define ADD64 "add %x[second], %x[second], #5\n"
#define RESET32 "mov %w[second], #42\n"
#define RESET64 "mov %x[second], #42\n"
#define OLDKILL "mov w9, wzr\n"
#define KILL32 "mov %w[second], #909\n"
#define KILL64 "mov %x[second], #909\n"
#define TEST "cmp %w[choose], #0\n"
#define ZERO(name) "b.eq " #name "_skipped\n"
#define JUMP(name) "b " #name "_join\n"
#define COUNT "add w11, %w[choose], #2\n"
#define AGAIN(name) "subs w11, w11, #1\nb.ne " #name "_loop\n"
#else
#error Unsupported merged-local runtime target
#endif
#define LABEL(name, suffix) ".globl " #name "_" #suffix "\n" #name "_" #suffix ":\n"
#define COPY(name, op_copy) LABEL(name, copy) op_copy LABEL(name, copied) "nop\n"
#define UPDATE(name, add) LABEL(name, update) add LABEL(name, updated) "nop\n"
#define STRAIGHT(name, op_copy, add, op_reset) \
    COPY(name, op_copy) LABEL(name, oldkill) OLDKILL LABEL(name, oldlost) "nop\n" UPDATE(name, add)
#define STALE(name, op_copy, add, op_reset) COPY(name, op_copy) UPDATE(name, add)
#define BRANCH(name, op_copy, add, op_reset) \
    TEST ZERO(name) COPY(name, op_copy) JUMP(name) \
    LABEL(name, skipped) "nop\n" LABEL(name, join) "nop\n" \
    LABEL(name, reset) op_reset LABEL(name, resetready) "nop\n" UPDATE(name, add)
#define LOOP(name, op_copy, add, op_reset) \
    COPY(name, op_copy) COUNT LABEL(name, loop) "nop\n" UPDATE(name, add) AGAIN(name)
#define FUNCTION(type, name, shape, def, op_copy, add, op_reset, op_kill) \
    __attribute__((noinline, noclone)) type name(type input, int choose) { \
        register type first __asm__(FIRST) = -12345; \
        register type second __asm__(SECOND) = -23456; \
        __asm__ volatile(LABEL(name, before) "nop\n" : "+r"(first), "+r"(second) : : "memory"); \
        __asm__ volatile(LABEL(name, definition) def LABEL(name, ready) "nop\n" \
            shape(name, op_copy, add, op_reset) LABEL(name, kill) op_kill LABEL(name, lost) "nop\n" \
            : [first] "+&r"(first), [second] "+&r"(second) \
            : [value] "r"(input + 7), [choose] "r"(choose) : COUNTER, "cc", "memory"); \
        return second; \
    }
typedef int count32;
typedef long long count64;
FUNCTION(count32, merged_straight32, STRAIGHT, DEF32, COPY32, ADD32, RESET32, KILL32)
FUNCTION(count64, merged_straight64, STRAIGHT, DEF64, COPY64, ADD64, RESET64, KILL64)
FUNCTION(count32, merged_stale32, STALE, DEF32, COPY32, ADD32, RESET32, KILL32)
FUNCTION(count64, merged_stale64, STALE, DEF64, COPY64, ADD64, RESET64, KILL64)
FUNCTION(count32, merged_branch32, BRANCH, DEF32, COPY32, ADD32, RESET32, KILL32)
FUNCTION(count64, merged_branch64, BRANCH, DEF64, COPY64, ADD64, RESET64, KILL64)
FUNCTION(count32, merged_loop32, LOOP, DEF32, COPY32, ADD32, RESET32, KILL32)
FUNCTION(count64, merged_loop64, LOOP, DEF64, COPY64, ADD64, RESET64, KILL64)
#define CHECK(name, input) if (name(input, choice) != 909) return 1;
__attribute__((noinline, noclone)) static int round_values(int small, long long large, int choice) {
    CHECK(merged_straight32, small)
    CHECK(merged_straight64, large)
    CHECK(merged_stale32, small)
    CHECK(merged_stale64, large)
    CHECK(merged_branch32, small)
    CHECK(merged_branch64, large)
    CHECK(merged_loop32, small)
    CHECK(merged_loop64, large)
    return 0;
}
int main(void) {
    return round_values(19, 19LL, 0) || round_values(19, 19LL, 1) ||
        round_values(-19, -19LL, 0) || round_values(-19, -19LL, 1) ||
        round_values(-1985229329, -81985529216486895LL, 0) ||
        round_values(-1985229329, -81985529216486895LL, 1);
}
