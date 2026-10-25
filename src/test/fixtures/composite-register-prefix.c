#include <stdint.h>

struct Pair { uint64_t first; uint64_t second; };
volatile uint64_t observed_first, observed_second;

__attribute__((noinline, noclone)) void capture_pair(struct Pair value)
{
#if defined(__x86_64__)
    __asm__ volatile(
        ".globl prefix_before\nprefix_before:\n\tnop\n"
        ".globl prefix_write\nprefix_write:\n\txorw %%di, %%di\n"
        ".globl prefix_after\nprefix_after:\n\tnop\n"
        : : "r"(value.first), "r"(value.second) : "rdi", "cc");
#elif defined(__aarch64__)
    __asm__ volatile(
        ".globl prefix_before\nprefix_before:\n\tnop\n"
        ".globl prefix_write\nprefix_write:\n\tmov w0, wzr\n"
        ".globl prefix_after\nprefix_after:\n\tnop\n"
        : : "r"(value.first), "r"(value.second) : "x0");
#else
#error selected research profiles only
#endif
    observed_first = value.first;
    observed_second = value.second;
}

int main(void)
{
    struct Pair value = { UINT64_C(0x1122334455667788), UINT64_C(0x99aabbccddeeff00) };
    capture_pair(value);
    return observed_first != value.first || observed_second != value.second;
}
