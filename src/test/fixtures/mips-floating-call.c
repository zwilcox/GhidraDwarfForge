/* Source-built debugger-call oracle. No register or target-mode manipulation. */
#ifdef FORGE_SCALAR_FLOAT
typedef float sample_scalar;
#else
typedef double sample_scalar;
#endif

volatile sample_scalar seen_a, seen_b;
volatile unsigned floating_calls, integer_calls;
volatile int seen_integer;

__attribute__((noinline)) sample_scalar fp_call(sample_scalar a, sample_scalar b) {
    seen_a = a;
    seen_b = b;
    floating_calls++;
    return a + b;
}

__attribute__((noinline)) int integer_call(int value) {
    seen_integer = value;
    integer_calls++;
    return value + 7;
}

__attribute__((noinline)) void marker(void) {
    __asm__ volatile("" ::: "memory");
}

int main(void) {
    sample_scalar floating = fp_call(21.5, -9.25);
    int integer = integer_call(5);
    marker();
    return floating == 12.25 && integer == 12 ? 0 : 1;
}
