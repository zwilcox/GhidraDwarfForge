/* Real CPUID versus ordinary calls with native intrinsic spellings. */
volatile unsigned context_result;

__attribute__((noinline)) unsigned halt_baddata(unsigned value) {
    return value + 7;
}

__attribute__((noinline)) unsigned cpuid_basic_info(unsigned value) {
    return value + 11;
}

__attribute__((noinline)) unsigned ordinary_context(unsigned value) {
    return halt_baddata(value) + cpuid_basic_info(value);
}

__attribute__((noinline)) unsigned intrinsic_context(void) {
    unsigned a = 0, b, c = 0, d;
    __asm__ volatile ("cpuid" : "+a" (a), "=b" (b), "+c" (c), "=d" (d));
    context_result = b ^ c ^ d;
    return a;
}

int main(void) {
    if (ordinary_context(3) != 24) return 1;
    (void)intrinsic_context();
    return 0;
}
