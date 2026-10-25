extern volatile int observed_calls;
__attribute__((noinline)) int perturb(int value)
{
    observed_calls++;
    return value * 2;
}
