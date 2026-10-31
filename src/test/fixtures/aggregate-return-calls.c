#include <stdint.h>

struct Triple { uint64_t first, second, third; };
struct Pair { uint32_t first, second; };
enum Choice { FIRST = 2, SECOND = 5 };
volatile uint32_t triple64_calls, triple32_calls, pair64_calls, scalar64_calls, words_calls;
volatile uint64_t sink;
int pointer_data = 100;

__attribute__((noinline, noclone)) struct Triple triple64(uint64_t seed, int delta)
{
    triple64_calls++;
    return (struct Triple){seed, seed + delta, seed ^ (uint32_t)delta};
}

__attribute__((noinline, noclone)) struct Triple triple32(uint32_t seed, int delta)
{
    triple32_calls++;
    return (struct Triple){seed, seed + delta, seed ^ (uint32_t)delta};
}

__attribute__((noinline, noclone)) struct Pair pair64(uint64_t seed, int delta)
{
    pair64_calls++;
    return (struct Pair){(uint32_t)seed, (uint32_t)(seed >> 32) + delta};
}

__attribute__((noinline, noclone)) uint64_t scalar64(uint64_t seed, int delta)
{
    scalar64_calls++;
    return seed + delta;
}

__attribute__((noinline, noclone)) struct Triple word_mix(signed char first,
    unsigned short second, enum Choice choice, int *pointer, uint32_t tail)
{
    words_calls++;
    return (struct Triple){first + *pointer, second + choice, tail};
}

struct Triple (*triple64_pointer)(uint64_t, int) = triple64;
struct Triple (*triple32_pointer)(uint32_t, int) = triple32;
struct Pair (*pair64_pointer)(uint64_t, int) = pair64;
uint64_t (*scalar64_pointer)(uint64_t, int) = scalar64;
struct Triple (*word_mix_pointer)(signed char, unsigned short, enum Choice, int *, uint32_t) = word_mix;

__attribute__((noinline, noclone)) void marker(void)
{
    __asm__ volatile ("" ::: "memory");
}

int main(void)
{
    uint64_t seed = UINT64_C(0x1122334455667788);
    struct Triple wide = triple64(seed, -19);
    struct Triple word = triple32(23, 7);
    struct Pair pair = pair64(seed, -19);
    uint64_t scalar = scalar64(seed, -19);
    struct Triple words = word_mix(-3, 23, FIRST, &pointer_data, 19);
    sink = word.second + words.first;
    int failed = wide.first != seed || wide.second != seed - 19 ||
        wide.third != (seed ^ UINT64_C(0xffffffed)) ||
        word.first != 23 || word.second != 30 || word.third != 16 ||
        pair.first != UINT32_C(0x55667788) || pair.second != UINT32_C(0x11223331) ||
        scalar != seed - 19 || words.first != 97 || words.second != 25 || words.third != 19 || sink != 127;
    marker();
    return failed;
}
