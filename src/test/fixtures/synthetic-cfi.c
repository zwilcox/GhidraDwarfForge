/* Freestanding compiler reference for ordinary nested/recursive unwind frames. */
#if defined(__x86_64__)
#define WITNESS_REGISTER "r12"
#elif defined(__aarch64__)
#define WITNESS_REGISTER "x19"
#else
#error Unsupported reference fixture target
#endif

volatile unsigned long cfi_sink;

__attribute__((noinline)) void cfi_checkpoint(void) {
    cfi_sink++;
}

__attribute__((noinline)) unsigned long cfi_recursive(unsigned long depth) {
    register unsigned long witness __asm__(WITNESS_REGISTER) = 0x5100 + depth;
    __asm__ volatile ("" : "+r" (witness));
    unsigned long result;
    if (depth != 0) {
        result = cfi_recursive(depth - 1);
    }
    else {
        cfi_checkpoint();
        result = 0;
    }
    __asm__ volatile ("" : "+r" (witness));
    return result + witness;
}

__attribute__((noinline)) unsigned long cfi_outer(void) {
    register unsigned long witness __asm__(WITNESS_REGISTER) = 0x6172;
    __asm__ volatile ("" : "+r" (witness));
    unsigned long result = cfi_recursive(3);
    __asm__ volatile ("" : "+r" (witness));
    return result + witness;
}

int cfi_main(void) {
    return cfi_outer() == 4 * 0x5100 + 6 + 0x6172 && cfi_sink == 1 ? 0 : 1;
}
