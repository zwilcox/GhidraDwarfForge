#include <stdint.h>

struct ReturnTriple { uint64_t first; uint64_t second; uint64_t third; };
volatile uint64_t observed_first, observed_second, observed_third;

__attribute__((noinline, noclone))
struct ReturnTriple make_result(uint64_t seed, int delta)
{
    struct ReturnTriple value;
    value.first = seed;
    value.second = seed + (uint64_t)(int64_t)delta;
    value.third = seed ^ (uint64_t)(uint32_t)delta;
    return value;
}

int main(void)
{
    struct ReturnTriple value = make_result(UINT64_C(0x1122334455667788), -19);
    observed_first = value.first;
    observed_second = value.second;
    observed_third = value.third;
    return observed_first != UINT64_C(0x1122334455667788) ||
        observed_second != UINT64_C(0x1122334455667775) ||
        observed_third != (UINT64_C(0x1122334455667788) ^ UINT64_C(0xffffffed));
}
