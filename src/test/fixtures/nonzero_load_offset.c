/* Source-built address regression: the ELF headers are outside every PT_LOAD. */
volatile int nonzero_sink = -1;

__attribute__((noinline)) int nonzero_add(int left, int right) {
    int sum = left + right;
    nonzero_sink = sum;
    return sum;
}

int nonzero_main(void) {
    return nonzero_add(19, 23) == 42 ? 0 : 1;
}
