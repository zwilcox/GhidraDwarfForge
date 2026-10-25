typedef unsigned long long wide_unsigned;
volatile wide_unsigned observed_wide;
volatile int observed_first;
volatile int observed_fifth;
volatile int observed_sixth;
volatile int observed_sum;

__attribute__((noinline)) void capture_wide(wide_unsigned value) {
    observed_wide = value;
}

__attribute__((noinline)) void capture_args(int first, int second, int third,
        int fourth, int fifth, int sixth) {
    observed_first = first;
    observed_fifth = fifth;
    observed_sixth = sixth;
    observed_sum = first + second + third + fourth + fifth + sixth;
}

int fixture_main(void) {
    capture_wide(0x1122334455667788ULL);
    capture_args(-19, 7, 11, 13, -37, 41);
    return observed_wide == 0x1122334455667788ULL && observed_first == -19 &&
        observed_fifth == -37 && observed_sixth == 41 && observed_sum == 16 ? 0 : 1;
}
