#include <stdlib.h>

#define KEEP __attribute__((noinline, noclone, used))

KEEP float scalar_float(float a, float b) { return a + b + 0.5f; }
KEEP double scalar_double(double a, double b) { return a - b + 0.25; }
KEEP long double source_helper(long double value) { return value + 0.125L; }
KEEP long double scalar_extended(long double a, long double b) { return source_helper(a + b); }

typedef long double ExtendedAlias;
ExtendedAlias extended_global = 6.25L;
ExtendedAlias extended_array[3] = {1.25L, 2.5L, -4.0L};
struct ExtendedRecord {
    int tag;
    ExtendedAlias value;
    int tail;
};
struct ExtendedRecord extended_record = {17, 8.75L, -23};

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
    if (extended_global != 6.25L || extended_array[2] != -4.0L) return 6;
    if (extended_record.tag != 17 || extended_record.value != 8.75L || extended_record.tail != -23) return 7;
    return 0;
}
