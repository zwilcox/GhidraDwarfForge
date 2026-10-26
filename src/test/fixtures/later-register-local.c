/* The compiler's nested held local ends before kill. Forge's separately curated
 * function-owned local intentionally has a different, documented scope. */
#include <stdint.h>
#if defined(__x86_64__)
#define HELD32 "r10"
#define HELD64 "r10"
#define RESULT "rax"
#define READ32 "movl %%r10d, %%eax"
#define READ64 "movq %%r10, %%rax"
#define KILL "xorl %%r10d, %%r10d"
#define CLOBBER "r10"
#elif defined(__aarch64__)
#define HELD32 "x9"
#define HELD64 "x9"
#define RESULT "x0"
#define READ32 "mov w0, w9"
#define READ64 "mov x0, x9"
#define KILL "mov x9, xzr"
#define CLOBBER "x9"
#else
#error Unsupported research profile
#endif
__attribute__((noinline)) int local32(int input) {
    register int result __asm__(RESULT);
    {
        register int held __asm__(HELD32) = input + 7;
        __asm__ volatile(".globl local32_read\nlocal32_read:\n\t" READ32
            : "=r"(result) : "r"(held) : "memory");
    }
    __asm__ volatile(".globl local32_kill\nlocal32_kill:\n\t" KILL
        "\n.globl local32_after\nlocal32_after:\n\tnop" : : : CLOBBER, "memory");
    return result;
}
__attribute__((noinline)) long long local64(long long input) {
    register long long result __asm__(RESULT);
    {
        register long long held __asm__(HELD64) = input + 7;
        __asm__ volatile(".globl local64_read\nlocal64_read:\n\t" READ64
            : "=r"(result) : "r"(held) : "memory");
    }
    __asm__ volatile(".globl local64_kill\nlocal64_kill:\n\t" KILL
        "\n.globl local64_after\nlocal64_after:\n\tnop" : : : CLOBBER, "memory");
    return result;
}
int main(void) {
#define ROUND(small, large) \
    if (local32(small) != (small) + 7 || local64(large) != (large) + 7) { return 1; }
    ROUND(19, 19)
    ROUND(-19, -19)
    ROUND(-1985229329, -81985529216486895LL)
#undef ROUND
    return 0;
}
