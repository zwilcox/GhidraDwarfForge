/* Source-known ARM base/VFP aggregate transfers, including register exhaustion. */
typedef struct Pair { int a; int b; } Pair;
typedef struct Float3 { float a; float b; float c; } Float3;
typedef struct Double2 { double a; double b; } Double2;
typedef struct Mixed { int a; float b; } Mixed;

Pair input_pair = {17, -23};
Float3 input_float3 = {1.25f, 2.5f, 4.75f};
Double2 input_double2 = {1.25, 2.5};
Mixed input_mixed = {17, 2.5f};
volatile Pair seen_pair;
volatile Float3 seen_float3;
volatile Double2 seen_double2;
volatile Mixed seen_mixed;
volatile int seen_ints[3];
volatile double seen_doubles[7];
volatile unsigned calls;

#define OBSERVE(PREFIX, KIND) \
    __asm__ volatile(".global " #PREFIX "_" #KIND "_observe\n" \
        #PREFIX "_" #KIND "_observe:" ::: "memory")

#define AGGREGATES(PREFIX, PCS) \
    __attribute__((noinline, pcs(PCS))) Pair PREFIX##_pair(Pair value) \
    { \
        ++calls; seen_pair = value; OBSERVE(PREFIX, pair); \
        value.a += 1; value.b += 2; return value; \
    } \
    __attribute__((noinline, pcs(PCS))) Float3 PREFIX##_float3(Float3 value) \
    { \
        ++calls; seen_float3 = value; OBSERVE(PREFIX, float3); \
        value.a += 1; value.b += 1; value.c += 1; return value; \
    } \
    __attribute__((noinline, pcs(PCS))) Double2 PREFIX##_double2(Double2 value) \
    { \
        ++calls; seen_double2 = value; OBSERVE(PREFIX, double2); \
        value.a += 1; value.b += 1; return value; \
    } \
    __attribute__((noinline, pcs(PCS))) Mixed PREFIX##_mixed(Mixed value) \
    { \
        ++calls; seen_mixed = value; OBSERVE(PREFIX, mixed); \
        value.a += 1; value.b += 1; return value; \
    } \
    __attribute__((noinline, pcs(PCS))) int PREFIX##_split(int a, int b, int c, Pair value) \
    { \
        ++calls; seen_ints[0] = a; seen_ints[1] = b; seen_ints[2] = c; seen_pair = value; OBSERVE(PREFIX, split); \
        return a + b + c + value.a + value.b; \
    } \
    __attribute__((noinline, pcs(PCS))) double PREFIX##_exhaust(double a, double b, double c, \
        double d, double e, double f, double g, Float3 value) \
    { \
        ++calls; seen_doubles[0] = a; seen_doubles[1] = b; seen_doubles[2] = c; \
        seen_doubles[3] = d; seen_doubles[4] = e; seen_doubles[5] = f; seen_doubles[6] = g; \
        seen_float3 = value; OBSERVE(PREFIX, exhaust); \
        return a + b + c + d + e + f + g + value.a + value.b + value.c; \
    }

AGGREGATES(base, "aapcs")
AGGREGATES(vfp, "aapcs-vfp")

#define POINTERS(PREFIX) \
    __typeof__(PREFIX##_pair) *PREFIX##_pair_pointer = PREFIX##_pair; \
    __typeof__(PREFIX##_float3) *PREFIX##_float3_pointer = PREFIX##_float3; \
    __typeof__(PREFIX##_double2) *PREFIX##_double2_pointer = PREFIX##_double2; \
    __typeof__(PREFIX##_mixed) *PREFIX##_mixed_pointer = PREFIX##_mixed; \
    __typeof__(PREFIX##_split) *PREFIX##_split_pointer = PREFIX##_split; \
    __typeof__(PREFIX##_exhaust) *PREFIX##_exhaust_pointer = PREFIX##_exhaust;

POINTERS(base)
POINTERS(vfp)

__attribute__((noinline)) void marker(void) { __asm__ volatile("" ::: "memory"); }

#define CHECK(PREFIX) \
    pair = PREFIX##_pair(input_pair); failed |= pair.a != 18 || pair.b != -21; \
    floats = PREFIX##_float3(input_float3); \
    failed |= floats.a != 2.25f || floats.b != 3.5f || floats.c != 5.75f; \
    doubles = PREFIX##_double2(input_double2); failed |= doubles.a != 2.25 || doubles.b != 3.5; \
    mixed = PREFIX##_mixed(input_mixed); failed |= mixed.a != 18 || mixed.b != 3.5f; \
    failed |= PREFIX##_split(7, 11, 13, input_pair) != 25; \
    failed |= PREFIX##_exhaust(1, 2, 3, 4, 5, 6, 7, input_float3) != 36.5;

int main(void)
{
    int failed = 0;
    Pair pair;
    Float3 floats;
    Double2 doubles;
    Mixed mixed;
    CHECK(base)
    CHECK(vfp)
    failed |= calls != 12;
    marker();
    return failed;
}
