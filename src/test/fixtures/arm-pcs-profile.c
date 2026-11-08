/* Source-known PCS arguments and returns; freestanding in both ARM data orders. */
volatile unsigned calls;
volatile float seen_float[2];
volatile double seen_double[10];
volatile long long seen_wide[2];

#define SCALAR(NAME, PCS, TYPE, SEEN) \
    __attribute__((noinline, pcs(PCS))) TYPE NAME(TYPE first, TYPE second) \
    { \
        ++calls; \
        SEEN[0] = first; \
        SEEN[1] = second; \
        return first + second; \
    }

SCALAR(base_float, "aapcs", float, seen_float)
SCALAR(vfp_float, "aapcs-vfp", float, seen_float)
SCALAR(base_double, "aapcs", double, seen_double)
SCALAR(vfp_double, "aapcs-vfp", double, seen_double)
SCALAR(base_wide, "aapcs", long long, seen_wide)
SCALAR(vfp_wide, "aapcs-vfp", long long, seen_wide)

#define MANY(NAME, PCS) \
    __attribute__((noinline, pcs(PCS))) double NAME(double a, double b, double c, double d, \
        double e, double f, double g, double h, double i, double j) \
    { \
        ++calls; \
        seen_double[0] = a; seen_double[1] = b; seen_double[2] = c; seen_double[3] = d; \
        seen_double[4] = e; seen_double[5] = f; seen_double[6] = g; seen_double[7] = h; \
        seen_double[8] = i; seen_double[9] = j; \
        return a + b + c + d + e + f + g + h + i + j; \
    }

MANY(base_many, "aapcs")
MANY(vfp_many, "aapcs-vfp")

#define POINTER(NAME, PCS, TYPE) TYPE (__attribute__((pcs(PCS))) *NAME##_pointer)(TYPE, TYPE) = NAME;
POINTER(base_float, "aapcs", float)
POINTER(vfp_float, "aapcs-vfp", float)
POINTER(base_double, "aapcs", double)
POINTER(vfp_double, "aapcs-vfp", double)
POINTER(base_wide, "aapcs", long long)
POINTER(vfp_wide, "aapcs-vfp", long long)

double (__attribute__((pcs("aapcs"))) *base_many_pointer)(double, double, double, double, double,
    double, double, double, double, double) = base_many;
double (__attribute__((pcs("aapcs-vfp"))) *vfp_many_pointer)(double, double, double, double, double,
    double, double, double, double, double) = vfp_many;

__attribute__((noinline)) void marker(void) { __asm__ volatile("" ::: "memory"); }

int main(void)
{
    int failed = 0;
    failed |= base_float(1.25f, 2.5f) != 3.75f;
    failed |= vfp_float(1.25f, 2.5f) != 3.75f;
    failed |= base_double(1.25, 2.5) != 3.75;
    failed |= vfp_double(1.25, 2.5) != 3.75;
    failed |= base_wide(0x123456789LL, -0x23456789LL) != 0x100000000LL;
    failed |= vfp_wide(0x123456789LL, -0x23456789LL) != 0x100000000LL;
    failed |= base_many(1, 2, 3, 4, 5, 6, 7, 8, 9, 10) != 55;
    failed |= vfp_many(1, 2, 3, 4, 5, 6, 7, 8, 9, 10) != 55;
    failed |= calls != 8;
    marker();
    return failed;
}
