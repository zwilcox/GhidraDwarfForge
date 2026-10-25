volatile int observed_numerator = -123;
volatile unsigned int observed_unsigned = 123;
volatile double observed_fp = 1.5;
volatile int observed_signed_result;
volatile unsigned int observed_unsigned_result;
volatile double observed_fp_result;
volatile int observed_calls;

__attribute__((noinline)) int recovered_signed(void)
{
    return observed_numerator / 3;
}

__attribute__((noinline)) unsigned int recovered_unsigned(void)
{
    return observed_unsigned / 3u;
}

__attribute__((noinline)) double recovered_double(void)
{
    return observed_fp + 0.25;
}

__attribute__((noinline)) volatile int *curated_pointer(void)
{
    return &observed_numerator;
}

__attribute__((noinline)) void curated_void(void)
{
    observed_calls++;
}

int main(void)
{
    observed_signed_result = recovered_signed();
    observed_unsigned_result = recovered_unsigned();
    observed_fp_result = recovered_double();
    curated_void();
    return observed_signed_result != -41 || observed_unsigned_result != 41u ||
        observed_fp_result != 1.75 || observed_calls != 1 || *curated_pointer() != -123;
}
