#include <stdlib.h>

#define KEEP __attribute__((noinline, noclone, used))

KEEP float scalar_float(float a, float b) { return a + b + 0.5f; }
KEEP double scalar_double(double a, double b) { return a - b + 0.25; }
KEEP long double scalar_extended(long double a, long double b) { return a + b + 0.125L; }

int main(void)
{
    unsigned char *memory = malloc(64);
    if (!memory) return 1;
    memory[0] = 23;
    memory[63] = 41;
    int result = memory[0] + memory[63];
    free(memory);
    if (result != 64) return 2;
    if (scalar_float(1.25f, 2.5f) != 4.25f) return 3;
    if (scalar_double(8.5, 2.25) != 6.5) return 4;
    if (scalar_extended(1.25L, 2.5L) != 3.875L) return 5;
    return 0;
}
