/* Linux AArch64 regression: SVC changes x0 without a raw p-code output.
 * The compiler saves value in another register. Forge must not infer that
 * migration or claim the original parameter remains in x0 after the syscall.
 * A negative input cannot accidentally equal a positive getpid result. */
#if !defined(__aarch64__) || !defined(__linux__)
#error This fixture requires the Linux AArch64 syscall ABI
#endif

volatile int opaque_sink = -1;

__attribute__((noinline)) void opaque_value(int value, volatile int *destination)
{
    register long number __asm__("x8") = 172; /* Linux AArch64 getpid. */
    __asm__ volatile(
        ".globl opaque_before\nopaque_before:\n\tsvc #0\n\tnop\n"
        : "+r"(number) : : "x0", "memory", "cc");
    /* Keep the asserted stop beyond the instruction adjacent to SVC: QEMU's
     * syscall stepping need not stop at that adjacent NOP. */
    __asm__ volatile(".globl opaque_store\nopaque_store:\n"
        : : "r"(value), "r"(destination) : "memory");
    *destination = value;
    __asm__ volatile(".globl opaque_return\nopaque_return:\n" : : : "memory");
}

int main(void)
{
    opaque_value(-19, &opaque_sink);
    return opaque_sink != -19;
}
