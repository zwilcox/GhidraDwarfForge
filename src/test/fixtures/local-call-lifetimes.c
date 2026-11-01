/* A compiler-tracked later local survives ordinary, independently inspected calls. */
#if defined(__x86_64__)
#define HELD "r12"
#define MOVE "movq %[value], %[held]\n"
#define JUMP "jmp local_call_split_resume\n"
#define GAP ".byte 0xcc,0xcc,0xcc\n"
#define CLOBBER "xorq %%r12,%%r12"
#elif defined(__aarch64__)
#define HELD "x19"
#define MOVE "mov %x[held], %x[value]\n"
#define JUMP "b local_call_split_resume\n"
#define GAP ".inst 0xd4200000\n"
#define CLOBBER "mov x19,xzr"
#else
#error Unsupported local-call runtime target
#endif
#define LABEL(name, suffix) ".globl " #name "_" #suffix "\n" #name "_" #suffix ":\n"

__attribute__((noinline, noclone)) long long inspected_leaf(long long input) {
    __asm__ volatile("" : "+r"(input));
    return input + 1;
}

/* The ABI restores this register, but the physical-write proof must not claim
 * it was untouched. GDB observes the temporary clobber inside the callee. */
__attribute__((noinline, noclone)) long long inspected_clobber(long long input) {
    __asm__ volatile(CLOBBER ::: HELD, "cc");
    return input + 1;
}

#define FUNCTION(name, body) \
    __attribute__((noinline, noclone)) long long name(long long input) { \
        long long result = input; \
        int count = input > 0 ? 2 : 3; \
        register long long held __asm__(HELD) = -12345; \
        __asm__ volatile(LABEL(name, before) "nop\n" : "+r"(held) : : "memory"); \
        __asm__ volatile(LABEL(name, definition) MOVE LABEL(name, ready) "nop\n" \
            : [held] "+&r"(held) : [value] "r"(input + 7) : "memory"); \
        body \
        __asm__ volatile(LABEL(name, after) "nop\n" : "+r"(held) : : "memory"); \
        return held + result; \
    }

FUNCTION(local_call_once, result = inspected_leaf(input);)
FUNCTION(local_call_twice, result = inspected_leaf(inspected_leaf(input));)
FUNCTION(local_call_branch,
    if (input > 0) result = inspected_leaf(input);
    else result = inspected_leaf(inspected_leaf(input));)
/* The counter has function scope: LLVM 18's call-site verifier stalls when a
 * call-site DIE is nested inside a lexical block. The loop still executes. */
FUNCTION(local_call_loop, while (count-- > 0) result = inspected_leaf(result);)
FUNCTION(local_call_split,
    __asm__ volatile(LABEL(local_call_split, jump) JUMP
        LABEL(local_call_split, gap) GAP LABEL(local_call_split, resume) "nop\n" ::: "memory");
    result = inspected_leaf(input);)
FUNCTION(local_call_clobber, result = inspected_clobber(input);)

__attribute__((noinline, noclone)) static int round_values(long long input) {
    return local_call_once(input) != input * 2 + 8 ||
        local_call_twice(input) != input * 2 + 9 ||
        local_call_branch(input) != input * 2 + (input > 0 ? 8 : 9) ||
        local_call_loop(input) != input * 2 + (input > 0 ? 9 : 10) ||
        local_call_split(input) != input * 2 + 8 ||
        local_call_clobber(input) != input * 2 + 8;
}

int main(void) {
    return round_values(19) || round_values(-19) || round_values(-81985529216486895LL);
}
