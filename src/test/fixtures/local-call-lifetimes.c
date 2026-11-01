/* A compiler-tracked later local survives ordinary, independently inspected calls. */
#if defined(__x86_64__)
#define HELD "r12"
#define MOVE "movq %[value], %[held]\n"
#elif defined(__aarch64__)
#define HELD "x19"
#define MOVE "mov %x[held], %x[value]\n"
#else
#error Unsupported local-call runtime target
#endif
#define LABEL(name, suffix) ".globl " #name "_" #suffix "\n" #name "_" #suffix ":\n"

__attribute__((noinline, noclone)) long long inspected_leaf(long long input) {
    __asm__ volatile("" : "+r"(input));
    return input + 1;
}

#define FUNCTION(name, calls) \
    __attribute__((noinline, noclone)) long long name(long long input) { \
        register long long held __asm__(HELD) = -12345; \
        __asm__ volatile(LABEL(name, before) "nop\n" : "+r"(held) : : "memory"); \
        __asm__ volatile(LABEL(name, definition) MOVE LABEL(name, ready) "nop\n" \
            : [held] "+&r"(held) : [value] "r"(input + 7) : "memory"); \
        long long result = (calls); \
        __asm__ volatile(LABEL(name, after) "nop\n" : "+r"(held) : : "memory"); \
        return held + result; \
    }

FUNCTION(local_call_once, inspected_leaf(input))
FUNCTION(local_call_twice, inspected_leaf(inspected_leaf(input)))

__attribute__((noinline, noclone)) static int round_values(long long input) {
    return local_call_once(input) != input * 2 + 8 ||
        local_call_twice(input) != input * 2 + 9;
}

int main(void) {
    return round_values(19) || round_values(-19) || round_values(-81985529216486895LL);
}
