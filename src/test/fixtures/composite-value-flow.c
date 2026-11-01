#include <stdint.h>

/* The test curator groups the two real scalar arguments into one custom Pair.
 * This is explicit analyst knowledge, not a claim about the original C ABI. */
volatile uint64_t effect_sink;
volatile uint8_t alias_sink;

#define MARK(name, point) ".globl " #name "_" #point "\n" #name "_" #point ":\n\t"
#if defined(__x86_64__)
#define MIXED_ARGS uint64_t first, uint64_t ignored, volatile uint8_t *unknown, \
    uint64_t pad3, uint64_t pad4, uint64_t pad5, uint64_t second
#define MIXED_CALL(name, a, b) name(a, 0, &alias_sink, 0, 0, 0, b)
#define REG_A "rdi"
#define REG_B "rsi"
#define REG_POINTER "rdx"
#define INPUT_SECOND "movq %[incoming], %%rsi\n\t"
#define SAVE_A "movq %%rdi, %[slot_a]\n\t"
#define SAVE_B "movq %%rsi, %[slot_b]\n\t"
#define KILL_A "xorq %%rdi, %%rdi\n\t"
#define KILL_B "xorq %%rsi, %%rsi\n\t"
#define LOAD_A "movq %[slot_a], %%r10\n\t"
#define LOAD_B "movq %[slot_b], %%r11\n\t"
#define CHANGE_SLOT "xorb $90, %[slot_a]\n\t"
#define KILL_LOADED "xorq %%r10, %%r10\n\t"
#define ALIAS_STORE "movb $127, (%%rdx)\n\t"
#define BRANCH_FLOW(name) "cmpb $0, (%%rdx)\n\tje 1f\n\t" \
    MARK(name, right) "movq %%rsi, %%r11\n\tjmp 2f\n1:\n\t" \
    MARK(name, left) "movq %%rsi, %%rax\n2:\n\t"
#define LOOP_FLOW(name) "movzbl (%%rdx), %%ecx\n\taddl $2, %%ecx\n1:\n\t" \
    MARK(name, loop) "movq %[slot_b], %%r11\n\txorq %%r11, %%r11\n\tdecl %%ecx\n\tjne 1b\n\t"
#define SPLIT_FLOW(name) "jmp 1f\n\t" MARK(name, hole) ".byte 0xcc,0xcc,0xcc\n1:\n\t" MARK(name, afterhole) "nop\n\t"
#define CALL_FLOW(name) "subq $32, %%rsp\n\tcall pieces_leaf\n\t" MARK(name, returned) "addq $32, %%rsp\n\t"
#define MEMORY_CALL(name) "subq $32, %%rsp\n\tcall pieces_memory_leaf\n\t" MARK(name, returned) "addq $32, %%rsp\n\t" MARK(name, restored) "nop\n\t"
#define UNKNOWN_CALL(name) "subq $32, %%rsp\n\tcall pieces_memory_alias\n\t" MARK(name, returned) "addq $32, %%rsp\n\t"
#define LOAD_A_SAVED "movq %[slot_a], %%rbx\n\t"
#define LOAD_B_SAVED "movq %[slot_b], %%r12\n\t"
#define KILL_SAVED "xorq %%rbx, %%rbx\n\t"
#define CLOBBERS "rax", "rcx", "rbx", "r12", "r10", "r11", "cc", "memory"
#elif defined(__aarch64__)
#define MIXED_ARGS uint64_t first, uint64_t ignored, volatile uint8_t *unknown, \
    uint64_t pad3, uint64_t pad4, uint64_t pad5, uint64_t pad6, uint64_t pad7, uint64_t second
#define MIXED_CALL(name, a, b) name(a, 0, &alias_sink, 0, 0, 0, 0, 0, b)
#define REG_A "x0"
#define REG_B "x1"
#define REG_POINTER "x2"
#define INPUT_SECOND "ldr x1, %[incoming]\n\t"
#define SAVE_A "str x0, %[slot_a]\n\t"
#define SAVE_B "str x1, %[slot_b]\n\t"
#define KILL_A "mov x0, xzr\n\t"
#define KILL_B "mov x1, xzr\n\t"
#define LOAD_A "ldr x9, %[slot_a]\n\t"
#define LOAD_B "ldr x10, %[slot_b]\n\t"
#define CHANGE_SLOT "ldrb w12, %[slot_a]\n\teor w12, w12, #0x2\n\tstrb w12, %[slot_a]\n\t"
#define KILL_LOADED "mov x9, xzr\n\t"
#define ALIAS_STORE "mov w12, #127\n\tstrb w12, [x2]\n\t"
#define BRANCH_FLOW(name) "ldrb w3, [x2]\n\tcbz w3, 1f\n\t" \
    MARK(name, right) "mov x10, x1\n\tb 2f\n1:\n\t" \
    MARK(name, left) "mov x11, x1\n2:\n\t"
#define LOOP_FLOW(name) "ldrb w3, [x2]\n\tadd w3, w3, #2\n1:\n\t" \
    MARK(name, loop) "ldr x10, %[slot_b]\n\tmov x10, xzr\n\tsubs w3, w3, #1\n\tb.ne 1b\n\t"
#define SPLIT_FLOW(name) "b 1f\n\t" MARK(name, hole) ".inst 0xd4200000\n1:\n\t" MARK(name, afterhole) "nop\n\t"
#define CALL_FLOW(name) "bl pieces_leaf\n\t" MARK(name, returned) "nop\n\t"
#define MEMORY_CALL(name) "bl pieces_memory_leaf\n\t" MARK(name, returned) "nop\n\t" MARK(name, restored) "nop\n\t"
#define UNKNOWN_CALL(name) "bl pieces_memory_alias\n\t" MARK(name, returned) "nop\n\t"
#define LOAD_A_SAVED "ldr x19, %[slot_a]\n\t"
#define LOAD_B_SAVED "ldr x20, %[slot_b]\n\t"
#define KILL_SAVED "mov x19, xzr\n\t"
#define CLOBBERS "x19", "x20", "x3", "x9", "x10", "x11", "x12", "x30", "cc", "memory"
#else
#error selected fixture profiles only
#endif

#define INCOMING_OPERAND , [incoming] "m"(second)
#define BODY(name, second_value, input_second, effect, extra_operand, flow, call, load_a, load_b, retire_a) \
    volatile uint64_t first_slot = UINT64_C(0x7777777777777777); \
    volatile uint64_t second_slot = UINT64_C(0x5555555555555555); \
    register uint64_t carrier_a __asm__(REG_A) = first; \
    register uint64_t carrier_b __asm__(REG_B) = second_value; \
    register volatile uint8_t *pointer __asm__(REG_POINTER) = unknown; \
    __asm__ volatile( \
        MARK(name, before) "nop\n\t" input_second \
        MARK(name, second_ready) "nop\n\t" SAVE_A \
        MARK(name, first_saved) "nop\n\t" KILL_A \
        MARK(name, first_memory) "nop\n\t" effect \
        MARK(name, alias_done) "nop\n\t" SAVE_B \
        MARK(name, second_saved) "nop\n\t" flow KILL_B \
        MARK(name, second_memory) "nop\n\t" load_a \
        MARK(name, first_loaded) "nop\n\t" CHANGE_SLOT \
        MARK(name, slot_changed) "nop\n\t" load_b \
        MARK(name, second_loaded) "nop\n\t" call retire_a \
        MARK(name, lost) "nop\n\t" load_a \
        MARK(name, stale) "nop\n\t" \
        : "+r"(carrier_a), "+r"(carrier_b), [slot_a] "+m"(first_slot), [slot_b] "+m"(second_slot) \
        : "r"(pointer) extra_operand : CLOBBERS); \
    effect_sink = first_slot ^ second_slot

__attribute__((noinline, noclone)) void pieces_registers(uint64_t first, uint64_t second, volatile uint8_t *unknown)
{
    BODY(pieces_registers, second, "", "", , "", "", LOAD_A, LOAD_B, KILL_LOADED);
}

__attribute__((noinline, noclone)) void pieces_mixed(MIXED_ARGS)
{
    BODY(pieces_mixed, 0, INPUT_SECOND, "", INCOMING_OPERAND, "", "", LOAD_A, LOAD_B, KILL_LOADED);
}

__attribute__((noinline, noclone)) void pieces_alias_registers(uint64_t first, uint64_t second, volatile uint8_t *unknown)
{
    BODY(pieces_alias_registers, second, "", ALIAS_STORE, , "", "", LOAD_A, LOAD_B, KILL_LOADED);
}

__attribute__((noinline, noclone)) void pieces_alias_mixed(MIXED_ARGS)
{
    BODY(pieces_alias_mixed, 0, INPUT_SECOND, ALIAS_STORE, INCOMING_OPERAND, "", "", LOAD_A, LOAD_B, KILL_LOADED);
}

__attribute__((noinline, noclone)) void pieces_branch(uint64_t first, uint64_t second, volatile uint8_t *unknown)
{
    BODY(pieces_branch, second, "", "", , BRANCH_FLOW(pieces_branch), "", LOAD_A, LOAD_B, KILL_LOADED);
}

__attribute__((noinline, noclone)) void pieces_loop(uint64_t first, uint64_t second, volatile uint8_t *unknown)
{
    BODY(pieces_loop, second, "", "", , LOOP_FLOW(pieces_loop), "", LOAD_A, LOAD_B, KILL_LOADED);
}

__attribute__((noinline, noclone)) void pieces_split(uint64_t first, uint64_t second, volatile uint8_t *unknown)
{
    BODY(pieces_split, second, "", "", , SPLIT_FLOW(pieces_split), "", LOAD_A, LOAD_B, KILL_LOADED);
}

__attribute__((noinline, noclone)) void pieces_leaf(void)
{
    __asm__ volatile("nop");
}

/* The positive fixture isolates SP-relative callee writes. A separate x86
 * control retains a frame-pointer save/restore that the current physical
 * nonwrite proof deliberately does not treat as register preservation. */
#if !FORGE_FRAME_LEAF
__attribute__((optimize("omit-frame-pointer")))
#endif
__attribute__((noinline, noclone)) void pieces_memory_leaf(void)
{
    volatile uint64_t scratch = UINT64_C(0x8877665544332211);
    __asm__ volatile("" : "+m"(scratch));
}

__attribute__((noinline, noclone)) void pieces_memory_alias(uint64_t first, uint64_t second, volatile uint8_t *pointer)
{
    *pointer = 127;
}

__attribute__((noinline, noclone)) void pieces_memory_registers(uint64_t first, uint64_t second, volatile uint8_t *unknown)
{
    BODY(pieces_memory_registers, second, "", "", , MEMORY_CALL(pieces_memory_registers), "", LOAD_A, LOAD_B, KILL_LOADED);
}

__attribute__((noinline, noclone)) void pieces_memory_mixed(MIXED_ARGS)
{
    BODY(pieces_memory_mixed, 0, INPUT_SECOND, "", INCOMING_OPERAND, MEMORY_CALL(pieces_memory_mixed), "", LOAD_A, LOAD_B, KILL_LOADED);
}

__attribute__((noinline, noclone)) void pieces_memory_unknown(uint64_t first, uint64_t second, volatile uint8_t *unknown)
{
    BODY(pieces_memory_unknown, second, "", "", , LOAD_B_SAVED UNKNOWN_CALL(pieces_memory_unknown), "", LOAD_A, LOAD_B, KILL_LOADED);
}

__attribute__((noinline, noclone)) void pieces_call(uint64_t first, uint64_t second, volatile uint8_t *unknown)
{
    BODY(pieces_call, second, "", "", , "", CALL_FLOW(pieces_call), LOAD_A_SAVED, LOAD_B_SAVED, KILL_SAVED);
}

__attribute__((noinline, noclone)) void pieces_volatile_call(uint64_t first, uint64_t second, volatile uint8_t *unknown)
{
    BODY(pieces_volatile_call, second, "", "", , "", CALL_FLOW(pieces_volatile_call), LOAD_A, LOAD_B, KILL_LOADED);
}

__attribute__((noinline, noclone)) void navigation_control(void)
{
    effect_sink += 1;
    effect_sink += 2;
    effect_sink += 3;
}

int main(void)
{
    uint64_t first = UINT64_C(0x1122334455667788), second = UINT64_C(0x99aabbccddeeff00);
#if defined(__x86_64__)
    uint64_t changed = first ^ 90;
#else
    uint64_t changed = first ^ 2;
#endif
    pieces_registers(first, second, &alias_sink);
    if (effect_sink != (changed ^ second)) return 1;
    MIXED_CALL(pieces_mixed, first, second);
    if (effect_sink != (changed ^ second)) return 2;
    pieces_alias_registers(first, second, &alias_sink);
    if (effect_sink != (changed ^ second) || alias_sink != 127) return 3;
    alias_sink = 0;
    MIXED_CALL(pieces_alias_mixed, first, second);
    if (effect_sink != (changed ^ second) || alias_sink != 127) return 4;
    alias_sink = 0;
    pieces_branch(first, second, &alias_sink);
    if (effect_sink != (changed ^ second)) return 5;
    alias_sink = 1;
    pieces_branch(first, second, &alias_sink);
    if (effect_sink != (changed ^ second)) return 6;
    alias_sink = 0;
    pieces_loop(first, second, &alias_sink);
    if (effect_sink != (changed ^ second)) return 7;
    alias_sink = 1;
    pieces_loop(first, second, &alias_sink);
    if (effect_sink != (changed ^ second)) return 8;
    pieces_split(first, second, &alias_sink);
    if (effect_sink != (changed ^ second)) return 11;
    pieces_memory_registers(first, second, &alias_sink);
    if (effect_sink != (changed ^ second)) return 12;
    MIXED_CALL(pieces_memory_mixed, first, second);
    if (effect_sink != (changed ^ second)) return 13;
    alias_sink = 0;
    pieces_memory_unknown(first, second, &alias_sink);
    if (effect_sink != (changed ^ second) || alias_sink != 127) return 14;
    pieces_call(first, second, &alias_sink);
    if (effect_sink != (changed ^ second)) return 9;
    pieces_volatile_call(first, second, &alias_sink);
    if (effect_sink != (changed ^ second)) return 10;
    navigation_control();
    return 0;
}
