/* Owned freestanding i386 ABI reference; no libc or host startup objects. */
struct pair { int first; int second; };
volatile int sink;
__attribute__((noinline)) int scalar(int first, int second) {
    int held = first + second;
    __asm__ volatile(".globl scalar_ready\nscalar_ready:\n\tnop" : : : "memory");
    sink = held;
    return held;
}
__attribute__((noinline)) long long wide(int first, long long second, int third) {
    long long held = second + first - third;
    __asm__ volatile(".globl wide_ready\nwide_ready:\n\tnop" : : : "memory");
    return held;
}
__attribute__((noinline)) int aggregate(struct pair value, int tail) {
    int held = value.first - value.second + tail;
    __asm__ volatile(".globl aggregate_ready\naggregate_ready:\n\tnop" : : : "memory");
    sink = held;
    return held;
}
__attribute__((noreturn)) void _start(void) {
    int ok = 1;
#define ROUND(first, second, large, tail) \
    { \
        struct pair value = { first, second }; \
        ok = ok && scalar(first, second) == (first) + (second); \
        ok = ok && wide(first, large, tail) == (large) + (first) - (tail); \
        ok = ok && aggregate(value, tail) == (first) - (second) + (tail); \
    }
    ROUND(-19, 42, 0x123456789abcdefLL, 7)
    ROUND(19, -42, -0x123456789abcdefLL, -7)
    ROUND(0x12345678, -1, -0x23456789abcdef0LL, 17)
#undef ROUND
    __asm__ volatile("int $0x80" : : "a"(1), "b"(ok ? 0 : 1) : "memory");
    __builtin_unreachable();
}
