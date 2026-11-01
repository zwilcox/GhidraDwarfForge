/* Compiler-owned stack objects and inspected/nonaliasing versus aliasing calls. */
#if defined(__x86_64__)
#define STORE "movq %[value], %[held]\n"
#elif defined(__aarch64__)
#define STORE "str %x[value], %[held]\n"
#else
#error Unsupported stack-call runtime target
#endif
#define LABEL(name, suffix) ".globl " #name "_" #suffix "\n" #name "_" #suffix ":\n"

__attribute__((noinline, noclone)) long long inspected_leaf(long long input) {
    volatile long long scratch = input;
    __asm__ volatile("" : "+m"(scratch));
    return input + 1;
}

__attribute__((noinline, noclone)) long long inspected_nested(long long input) {
    long long result = inspected_leaf(input);
    __asm__ volatile("nop" : "+r"(result));
    return result + 1;
}

__attribute__((noinline, noclone)) long long inspected_alias(long long *destination, long long input) {
    *destination = 909;
    return input + 1;
}

#define FUNCTION(name, call) \
    __attribute__((noinline, noclone)) long long name(long long input) { \
        long long held; \
        __asm__ volatile(LABEL(name, definition) STORE LABEL(name, ready) "nop\n" \
            : [held] "=m"(held) : [value] "r"(input + 7) : "memory"); \
        long long result = (call); \
        __asm__ volatile(LABEL(name, after) "nop\n" : "+m"(held) : : "memory"); \
        return held + result; \
    }

FUNCTION(local_call_once, inspected_leaf(input))
FUNCTION(local_call_twice, inspected_nested(input))
FUNCTION(local_call_alias, inspected_alias(&held, input))

__attribute__((noinline, noclone)) static int round_values(long long input) {
    return local_call_once(input) != input * 2 + 8 || local_call_twice(input) != input * 2 + 9 ||
        local_call_alias(input) != 909 + input + 1;
}

int main(void) {
    return round_values(19) || round_values(-19) || round_values(-81985529216486895LL);
}
