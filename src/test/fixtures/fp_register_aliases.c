/* Scalar floating arguments retain their values across ordinary memory stores.
 * Compiler DWARF is an independent oracle; Forge imports the stripped copy. */
volatile float fp_float_first = -1.0f;
volatile float fp_float_second = -1.0f;
volatile double fp_double_first = -1.0;
volatile double fp_double_second = -1.0;
volatile float fp_clobber_sink = -1.0f;

#define MARKER(name) __asm__ volatile(".globl " #name "\n" #name ":\n\tnop\n" ::: "memory")

__attribute__((noinline)) void fp_float(float first, float second)
{
    MARKER(fp_float_before);
    fp_float_first = first;
    fp_float_second = second;
    MARKER(fp_float_after);
}

__attribute__((noinline)) void fp_double(double first, double second)
{
    MARKER(fp_double_before);
    fp_double_first = first;
    fp_double_second = second;
    MARKER(fp_double_after);
}

#if !defined(__mips__)
__attribute__((noinline)) void fp_clobbered(float value)
{
    fp_clobber_sink = value;
    MARKER(fp_clobber_before);
#if defined(__x86_64__)
    __asm__ volatile(".globl fp_clobber_write\nfp_clobber_write:\n\tpxor %%xmm0, %%xmm0\n"
        ::: "xmm0");
#elif defined(__aarch64__)
    __asm__ volatile(".globl fp_clobber_write\nfp_clobber_write:\n\tfmov s0, wzr\n"
        ::: "v0");
#elif defined(__arm__)
    __asm__ volatile(".globl fp_clobber_write\nfp_clobber_write:\n\tvmov s0, %0\n"
        : : "r"(0) : "s0");
#else
#error unsupported scalar floating fixture target
#endif
    MARKER(fp_clobber_after);
}
#endif

int main(void)
{
    fp_float(19.25f, -7.5f);
    fp_double(21.5, -9.25);
#if !defined(__mips__)
    fp_clobbered(13.75f);
    if (fp_clobber_sink != 13.75f) {
        return 1;
    }
#endif
    return fp_float_first != 19.25f || fp_float_second != -7.5f ||
        fp_double_first != 21.5 || fp_double_second != -9.25;
}
