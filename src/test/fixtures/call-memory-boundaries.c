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
#elif defined(__aarch64__)
#define ZERO_BYTE "strb wzr, %0\n"
#define RELEASE "add sp, sp, #16\n"
#define RESTORE "sub sp, sp, #16\n"
#define UNKNOWN_SP "mov x9, sp\neor x9, x9, #16\neor x9, x9, #16\nmov sp, x9\n"
#define TEMPORARY "x9"
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

__attribute__((noinline, noclone)) static int round_values(long long input) {
    return local_call_overlap(input) != input * 2 + 8 ||
        local_call_adjacent(input) != input * 2 + 8 ||
        local_call_released(input) != input * 2 + 8 ||
        local_call_unknown(input) != input * 2 + 8;
}

int main(void) {
    return round_values(19) || round_values(-19) || round_values(-81985529216486895LL);
}
