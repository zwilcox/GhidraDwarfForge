extern int perturb(int value);
volatile int observed_before;
volatile int observed_after;
volatile int observed_result;
volatile int observed_calls;

__attribute__((noinline)) int carry_across_call(int value)
{
    observed_before = value;
    int response = perturb(value + 3);
    observed_after = value;
    return value + response;
}

int main(void)
{
#define CHECK(value, count) \
    observed_result = carry_across_call(value); \
    if (observed_before != (value) || observed_after != (value) || \
            observed_result != (value) * 3 + 6 || observed_calls != (count)) { return 1; }
    CHECK(17, 1)
    CHECK(-17, 2)
    CHECK(0x1234567, 3)
#undef CHECK
    return 0;
}
