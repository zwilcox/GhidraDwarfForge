/* Separate -O1 translation unit: ordinary scalar carrier, no register selection. */
volatile unsigned long long observed_scalar;

__attribute__((noinline)) void capture_scalar(unsigned long long value) {
    observed_scalar = value;
}
