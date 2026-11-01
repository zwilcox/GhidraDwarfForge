#ifndef FORGE_AARCH64_ABI_H
#define FORGE_AARCH64_ABI_H

typedef struct { long long first, second; } AbiPair;
typedef struct { long long first, second, third; } AbiLarge;
typedef struct { float first, second, third, fourth; } AbiHfa;

extern volatile unsigned int probe_calls;
long long abi_words(long long, long long, long long, long long, long long,
    long long, long long, long long, long long, long long);
double abi_floats(double, double, double, double, double, double, double,
    double, double, double);
AbiPair abi_pair(AbiPair);
AbiLarge abi_large(AbiLarge);
long long abi_large_stack(long long, long long, long long, long long,
    long long, long long, long long, long long, AbiLarge);
AbiLarge abi_large_spill(AbiLarge);
AbiLarge abi_large_spill_alias(AbiLarge);
AbiHfa abi_hfa(AbiHfa);
double abi_hfa_exhausted(double, double, double, double, double, double,
    double, AbiHfa, double);

long long abi_narrow_stack(long long, long long, long long, long long,
    long long, long long, long long, long long, signed char, unsigned short, int, long long);
__int128 abi_aligned_stack(long long, long long, long long, long long,
    long long, long long, long long, long long, signed char, __int128, signed char);
__int128 abi_aligned_register(long long, __int128, long long);
long long abi_pair_stack(long long, long long, long long, long long,
    long long, long long, long long, AbiPair, long long);
long long abi_pair_chain(long long, long long, long long, long long, long long,
    long long, long long, AbiPair, long long, __int128, AbiLarge, double);
long long abi_pair_variadic(long long, long long, long long, long long,
    long long, long long, long long, AbiPair, long long, ...);
#define ABI_WIDE_POS (((__int128)0x1234567890abcdefLL << 64) | 0x0fedcba987654321ULL)

#endif
