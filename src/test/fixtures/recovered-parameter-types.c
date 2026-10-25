volatile int scalar_result;
volatile int pointer_result;
volatile double floating_result;
volatile long ambiguous_result;
volatile int curated_result;

__attribute__((noinline)) int inferred_scalar(int seed)
{
    return seed / 3;
}

__attribute__((noinline)) int inferred_pointer(int *cursor)
{
    return *cursor / 3;
}

__attribute__((noinline)) double inferred_floating(double scale)
{
    return scale + 0.25;
}

__attribute__((noinline)) long unresolved_pair(long seed, long *cursor)
{
    *cursor = seed;
    return seed;
}

__attribute__((noinline)) int curated_scalar(int analyst_seed)
{
    return analyst_seed / 3;
}

int main(void)
{
    int value = 123;
    long copied = 0;
    scalar_result = inferred_scalar(-123);
    pointer_result = inferred_pointer(&value);
    floating_result = inferred_floating(1.5);
    ambiguous_result = unresolved_pair(17, &copied);
    curated_result = curated_scalar(123);
    return scalar_result != -41 || pointer_result != 41 || floating_result != 1.75 ||
        ambiguous_result != 17 || copied != 17 || curated_result != 41;
}
