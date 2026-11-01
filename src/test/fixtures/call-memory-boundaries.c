/* Known callee-entry-relative writes to an outgoing argument copy.
 * The caller's original held value remains live: the test curates its stack
 * copy, not the callee's distinct parameter object, as the saved location.
 */
#if defined(__x86_64__)
#define ZERO_BYTE "movb $0, %0\n"
#define RELEASE "addq $40, %%rsp\n"
#define RESTORE "subq $40, %%rsp\n"
#define UNKNOWN_SP "movq %%rsp, %%r10\nxorq $16, %%r10\nxorq $16, %%r10\nmovq %%r10, %%rsp\n"
#define TEMPORARY "r10"
#define FRAME_REGISTER "r12"
#define HELD_REGISTER "r13"
#define RESULT_REGISTER "rax"
#define SAVE_SP "movq %%rsp, %0\n"
#define RESTORE_SP "movq %0, %%rsp\n"
#define DIFFERENT_RETURN "ret $16\n"
#elif defined(__aarch64__)
#define ZERO_BYTE "strb wzr, %0\n"
#define RELEASE "add sp, sp, #16\n"
#define RESTORE "sub sp, sp, #16\n"
#define UNKNOWN_SP "mov x9, sp\neor x9, x9, #16\neor x9, x9, #16\nmov sp, x9\n"
#define TEMPORARY "x9"
#define FRAME_REGISTER "x19"
#define HELD_REGISTER "x20"
#define RESULT_REGISTER "x0"
#define SAVE_SP "mov %0, sp\n"
#define RESTORE_SP "mov sp, %0\n"
#define DIFFERENT_RETURN ".cfi_remember_state\nsub sp, sp, #16\n.cfi_adjust_cfa_offset 16\nret\n.cfi_restore_state\n"
#else
#error Unsupported call-memory boundary runtime target
#endif
#define LABEL(name, suffix) ".globl " #name "_" #suffix "\n" #name "_" #suffix ":\n"

#define SIGNATURE(name) \
    __attribute__((noinline, noclone)) long long name(long long input, \
            long long p1, long long p2, long long p3, long long p4, \
            long long p5, long long p6, long long p7, long long held, unsigned int adjacent)
#define KEEP_ARGUMENTS \
    __asm__ volatile("" : : "r"(p1), "r"(p2), "r"(p3), "r"(p4), \
        "r"(p5), "r"(p6), "r"(p7), "m"(held), "m"(adjacent))

#define HELPER(name, object) \
    SIGNATURE(name) { \
        __asm__ volatile(LABEL(name, write) ZERO_BYTE LABEL(name, written) "nop\n" \
            : "+m"(((unsigned char *)&object)[2]) : : "memory"); \
        KEEP_ARGUMENTS; \
        return input + 1; \
    }

HELPER(inspected_overlap, held)
HELPER(inspected_adjacent, adjacent)

SIGNATURE(inspected_released) {
    /* There is no call or memory access while SP is temporarily displaced;
     * the complete asm statement restores the compiler-visible SP. */
    __asm__ volatile(LABEL(inspected_released, write) RELEASE
        LABEL(inspected_released, released) "nop\n" RESTORE
        LABEL(inspected_released, written) "nop\n" : : : "memory", "cc");
    KEEP_ARGUMENTS;
    return input + 1;
}

SIGNATURE(inspected_unknown) {
    /* The two XORs cancel at runtime. The affine proof deliberately does not
     * assume this unsupported value transformation preserves an SP address.
     */
    __asm__ volatile(LABEL(inspected_unknown, write) UNKNOWN_SP
        LABEL(inspected_unknown, written) "nop\n" : : : TEMPORARY, "memory", "cc");
    KEEP_ARGUMENTS;
    return input + 1;
}

SIGNATURE(inspected_incompatible) {
    KEEP_ARGUMENTS;
    __asm__ volatile(LABEL(inspected_incompatible, written) "nop\n" : : : "memory");
    if (input < 0) {
        register long long result __asm__(RESULT_REGISTER) = input + 1;
        /* This intentionally violates ordinary ABI stack cleanup. Its caller
         * restores SP immediately; the exporter must reject a common memory
         * contract instead of trusting the selected default convention.
         */
        __asm__ volatile(DIFFERENT_RETURN : : "r"(result) : "memory");
        __builtin_unreachable();
    }
    return input + 1;
}

#define CALLER(name, helper) \
    __attribute__((noinline, noclone)) long long name(long long input) { \
        long long held = input + 7; \
        __asm__ volatile("" : "+r"(held)); \
        long long result = helper(input, input + 1, input + 2, input + 3, input + 4, \
            input + 5, input + 6, input + 7, held, 0x11223344U); \
        __asm__ volatile(LABEL(name, after) "nop\n" : "+r"(result)); \
        return held + result; \
    }

CALLER(local_call_overlap, inspected_overlap)
CALLER(local_call_adjacent, inspected_adjacent)
CALLER(local_call_released, inspected_released)
CALLER(local_call_unknown, inspected_unknown)

__attribute__((noinline, noclone)) long long local_call_incompatible(long long input) {
    register long long held __asm__(HELD_REGISTER) = input + 7;
    register unsigned long saved_sp __asm__(FRAME_REGISTER);
    __asm__ volatile("" : "+r"(held));
    __asm__ volatile(SAVE_SP : "=r"(saved_sp) : : "memory");
    long long result = inspected_incompatible(input, input + 1, input + 2, input + 3, input + 4,
        input + 5, input + 6, input + 7, held, 0x11223344U);
    __asm__ volatile(LABEL(local_call_incompatible, restore) RESTORE_SP
        LABEL(local_call_incompatible, after) "nop\n" : : "r"(saved_sp) : "memory");
    __asm__ volatile("" : "+r"(held), "+r"(result));
    return held + result;
}

__attribute__((noinline, noclone)) static int round_values(long long input) {
    return local_call_overlap(input) != input * 2 + 8 ||
        local_call_adjacent(input) != input * 2 + 8 ||
        local_call_released(input) != input * 2 + 8 ||
        local_call_unknown(input) != input * 2 + 8 ||
        local_call_incompatible(input) != input * 2 + 8;
}

int main(void) {
    return round_values(19) || round_values(-19) || round_values(-81985529216486895LL);
}
