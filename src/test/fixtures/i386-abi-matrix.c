#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef float Vector4 __attribute__((vector_size(16)));
struct Pair { int left; int right; };
struct Mixed { int code; double value; float fraction; };
#define KEEP __attribute__((noinline, noclone, used))

KEEP float scalar_float(float a, float b) { return a + b + 0.5f; }
KEEP double scalar_double(double a, double b) { return a - b + 0.25; }
KEEP long double scalar_extended(long double a, long double b) { return a + b + 0.125L; }
KEEP Vector4 vector_add(Vector4 a, Vector4 b) { return a + b; }
KEEP struct Pair pair_return(struct Pair value, int tail)
{
    value.left += tail;
    value.right -= tail;
    return value;
}
KEEP struct Mixed mixed_return(int leading, struct Mixed value, int tail)
{
    value.code += leading + tail;
    value.value += 0.5;
    value.fraction -= 0.25f;
    return value;
}
KEEP __attribute__((sseregparm)) double sse_parameters(double a, double b, double c) { return a + b - c; }
KEEP __attribute__((regparm(3))) int register_parameters(int a, int b, int c, int d) { return a + 2*b + 3*c + d; }
KEEP __attribute__((stdcall)) int stdcall_parameters(int a, int b, int c) { return a - b + c; }
KEEP __attribute__((fastcall)) int fastcall_parameters(int a, int b, int c) { return a + b - c; }
KEEP __attribute__((thiscall)) int thiscall_parameters(struct Pair *object, int tail) { return object->left + object->right + tail; }

int main(void)
{
    void *allocation = malloc(64);
    if (!allocation) return 2;
    memset(allocation, 0x5a, 64);
    unsigned char copy[64];
    memcpy(copy, allocation, 64);
    free(allocation);
    if (copy[0] != 0x5a || copy[63] != 0x5a) return 3;
    struct Pair pair = {7, -3};
    struct Mixed mixed = {19, 2.5, 1.25f};
    Vector4 left = {1.0f, 2.0f, 3.0f, 4.0f};
    Vector4 right = {0.5f, 1.5f, 2.5f, 3.5f};
    if (scalar_float(1.25f, 2.5f) != 4.25f) return 4;
    if (scalar_double(8.5, 2.25) != 6.5) return 5;
    if (scalar_extended(1.25L, 2.5L) != 3.875L) return 6;
    Vector4 result = vector_add(left, right);
    if (result[0] != 1.5f || result[1] != 3.5f || result[2] != 5.5f || result[3] != 7.5f) return 7;
    struct Pair pair_result = pair_return(pair, 5);
    if (pair_result.left != 12 || pair_result.right != -8) return 8;
    struct Mixed mixed_result = mixed_return(7, mixed, -2);
    if (mixed_result.code != 24 || mixed_result.value != 3.0 || mixed_result.fraction != 1.0f) return 9;
    if (sse_parameters(1.25, 8.5, 2.25) != 7.5) return 10;
    if (register_parameters(1, 2, 3, 4) != 18) return 11;
    if (stdcall_parameters(11, 4, 2) != 9) return 12;
    if (fastcall_parameters(11, 4, 2) != 13) return 13;
    if (thiscall_parameters(&pair, 5) != 9) return 14;
    puts("i386 ABI reference PASS");
    return 0;
}
