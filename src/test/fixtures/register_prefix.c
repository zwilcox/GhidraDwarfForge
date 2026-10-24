/* Compiler-DWARF oracle for an incoming value whose original register is
 * overwritten. Its direct saved-register copy is now covered by Forge's
 * bounded copy proof; register-copy.c also tests destruction of that copy. */
volatile int prefix_sink = -1;

__attribute__((noinline)) int prefix_value(int value)
{
#if defined(__x86_64__)
    __asm__ volatile(
        ".globl prefix_before\nprefix_before:\n\tnop\n"
        ".globl prefix_write\nprefix_write:\n\txorw %%di, %%di\n"
        : : "r"(value) : "rdi", "cc");
#elif defined(__aarch64__)
    __asm__ volatile(
        ".globl prefix_before\nprefix_before:\n\tnop\n"
        ".globl prefix_write\nprefix_write:\n\tmov w0, wzr\n"
        : : "r"(value) : "x0");
#else
#error unsupported register-prefix fixture target
#endif
    /* A separate C statement lets the compiler's DWARF describe the saved
     * value after the opaque asm clobber instead of its entry to that asm. */
    __asm__ volatile(".globl prefix_after\nprefix_after:\n\tnop\n" : : "r"(value));
    prefix_sink = value;
    return value;
}

int main(void)
{
    return prefix_value(19) != 19 || prefix_sink != 19;
}
