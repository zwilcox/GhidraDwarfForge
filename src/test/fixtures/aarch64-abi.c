/* Source-built AAPCS64 argument/return probes; no injected register storage. */
typedef struct { long long first, second; } AbiPair;
typedef struct { long long first, second, third; } AbiLarge;
typedef struct { float first, second, third, fourth; } AbiHfa;

volatile unsigned int probe_calls;

#ifdef __clang__
#define PROBE __attribute__((noinline))
#else
#define PROBE __attribute__((noinline, noclone))
#endif

PROBE long long abi_words(long long a, long long b, long long c, long long d,
    long long e, long long f, long long g, long long h, long long i, long long j)
{
    probe_calls++;
    return a + b + c + d + e + f + g + h + i + j;
}

PROBE double abi_floats(double a, double b, double c, double d, double e,
    double f, double g, double h, double i, double j)
{
    probe_calls++;
    return a + b + c + d + e + f + g + h + i + j;
}

PROBE AbiPair abi_pair(AbiPair value)
{
    probe_calls++;
    return (AbiPair) { value.first + 1, value.second + 2 };
}

PROBE AbiLarge abi_large(AbiLarge value)
{
    probe_calls++;
    return (AbiLarge) { value.first + 1, value.second + 2, value.third + 3 };
}

PROBE long long abi_large_stack(long long a, long long b, long long c, long long d,
    long long e, long long f, long long g, long long h, AbiLarge value)
{
    probe_calls++;
    return a + b + c + d + e + f + g + h + value.first + value.second + value.third;
}

static __attribute__((always_inline)) inline void clobber_integer_carriers(void)
{
    /* Real register writes force the ABI pointer through compiler-owned memory.
     * The compiler preserves the caller's callee-saved registers and link value.
     * Keep the frame register available for its normal frame bookkeeping. */
    __asm__ volatile (
        "mov x0, xzr\nmov x1, xzr\nmov x2, xzr\nmov x3, xzr\n"
        "mov x4, xzr\nmov x5, xzr\nmov x6, xzr\nmov x7, xzr\n"
        "mov x8, xzr\nmov x9, xzr\nmov x10, xzr\nmov x11, xzr\n"
        "mov x12, xzr\nmov x13, xzr\nmov x14, xzr\nmov x15, xzr\n"
        "mov x16, xzr\nmov x17, xzr\nmov x18, xzr\nmov x19, xzr\n"
        "mov x20, xzr\nmov x21, xzr\nmov x22, xzr\nmov x23, xzr\n"
        "mov x24, xzr\nmov x25, xzr\nmov x26, xzr\nmov x27, xzr\n"
        "mov x28, xzr\nmov x30, xzr"
        : : : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
        "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
        "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
        "x24", "x25", "x26", "x27", "x28", "x30", "memory");
}

PROBE AbiLarge abi_large_spill(AbiLarge value)
{
    clobber_integer_carriers();
    return (AbiLarge) { value.first + 1, value.second + 2, value.third + 3 };
}

/* The unrelated store is deliberately not proven nonaliasing by the exporter.
 * Its pointer slot must become unavailable, including after the later reload. */
PROBE AbiLarge abi_large_spill_alias(AbiLarge value)
{
    probe_calls++;
    clobber_integer_carriers();
    return (AbiLarge) { value.first + 1, value.second + 2, value.third + 3 };
}

PROBE AbiHfa abi_hfa(AbiHfa value)
{
    probe_calls++;
    return (AbiHfa) { value.first + 1.0f, value.second + 2.0f,
        value.third + 3.0f, value.fourth + 4.0f };
}

PROBE double abi_hfa_exhausted(double a, double b, double c, double d,
    double e, double f, double g, AbiHfa value, double tail)
{
    probe_calls++;
    return a + b + c + d + e + f + g + value.first + value.second +
        value.third + value.fourth + tail;
}

int main(void)
{
    volatile long long words = abi_words(11, 22, 33, 44, 55, 66, 77, 88, 909, -1010);
    volatile double floats = abi_floats(1.25, 2.5, 3.75, 4, 5, 6, 7, 8, 9.5, -10.25);
    AbiPair pair = abi_pair((AbiPair) { 101, -202 });
    AbiLarge large = abi_large((AbiLarge) { 303, -404, 505 });
    volatile long long large_stack = abi_large_stack(1, 2, 3, 4, 5, 6, 7, 8,
        (AbiLarge) { 303, -404, 505 });
    AbiLarge spilled = abi_large_spill((AbiLarge) { 303, -404, 505 });
    AbiLarge alias = abi_large_spill_alias((AbiLarge) { 303, -404, 505 });
    AbiHfa hfa = abi_hfa((AbiHfa) { 1.25f, -2.5f, 3.75f, 4.5f });
    volatile double exhausted = abi_hfa_exhausted(1, 2, 3, 4, 5, 6, 7,
        (AbiHfa) { 1.25f, -2.5f, 3.75f, 4.5f }, 9.5);
    return !(probe_calls == 8 && words == 295 && floats == 36.75 && pair.first == 102 && pair.second == -200 &&
        large.first == 304 && large.second == -402 && large.third == 508 && large_stack == 440 &&
        spilled.first == 304 && spilled.second == -402 && spilled.third == 508 &&
        alias.first == 304 && alias.second == -402 && alias.third == 508 &&
        hfa.first == 2.25f && hfa.second == -0.5f && hfa.third == 6.75f &&
        hfa.fourth == 8.5f && exhausted == 44.5);
}
