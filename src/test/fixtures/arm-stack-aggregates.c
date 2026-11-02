/* Natural C aggregates at core/VFP exhaustion and stack-alignment boundaries. */
typedef struct Pair { int first; int second; } Pair;
typedef struct Aligned { unsigned long long first; int second; } Aligned;
typedef struct __attribute__((packed)) Packed { unsigned char first; unsigned second; } Packed;
typedef struct Bytes { unsigned char first; unsigned char second; unsigned char third; } Bytes;
typedef struct Words { int items[3]; } Words;
typedef struct Mixed { float first; unsigned long long second; } Mixed;
typedef struct Floats { float first; float second; float third; } Floats;

Pair input_pair = {17, -23};
Aligned input_aligned = {0x1122334455667788ull, -23};
Packed input_packed = {0x91, 0x23456789u};
Bytes input_bytes = {0x91, 0xa2, 0xb3};
Words input_words = {{17, -23, 31}};
Mixed input_mixed = {1.25f, 0x1122334455667788ull};
Floats input_floats = {1.25f, 2.5f, 4.75f};
volatile Pair seen_pair;
volatile Aligned seen_aligned;
volatile Packed seen_packed;
volatile Bytes seen_bytes;
volatile Words seen_words;
volatile Mixed seen_mixed;
volatile Floats seen_floats;
volatile int seen_leading[3];
volatile int seen_tail;
volatile double seen_doubles[7];
volatile float seen_float_tail;

#define OBSERVE(PREFIX, KIND) \
    __asm__ volatile(".global " #PREFIX "_" #KIND "_observe\n" \
        #PREFIX "_" #KIND "_observe:" ::: "memory")
#define ORDINARY(PREFIX, PCS, KIND, TYPE, CHECK) \
    __attribute__((noinline, pcs(PCS))) int PREFIX##_##KIND(int a, int b, int c, TYPE value, int tail) \
    { \
        seen_leading[0] = a; seen_leading[1] = b; seen_leading[2] = c; \
        seen_##KIND = value; seen_tail = tail; OBSERVE(PREFIX, KIND); \
        return a == 7 && b == 11 && c == 13 && tail == -41 && (CHECK); \
    }
#define PROFILE(PREFIX, PCS) \
    ORDINARY(PREFIX, PCS, pair, Pair, value.first == 17 && value.second == -23) \
    ORDINARY(PREFIX, PCS, aligned, Aligned, value.first == 0x1122334455667788ull && value.second == -23) \
    ORDINARY(PREFIX, PCS, packed, Packed, value.first == 0x91 && value.second == 0x23456789u) \
    ORDINARY(PREFIX, PCS, bytes, Bytes, value.first == 0x91 && value.second == 0xa2 && value.third == 0xb3) \
    ORDINARY(PREFIX, PCS, words, Words, value.items[0] == 17 && value.items[1] == -23 && value.items[2] == 31) \
    ORDINARY(PREFIX, PCS, mixed, Mixed, value.first == 1.25f && value.second == 0x1122334455667788ull) \
    __attribute__((noinline, pcs(PCS))) int PREFIX##_floats(double a, double b, double c, \
        double d, double e, double f, double g, Floats value, float tail) \
    { \
        seen_doubles[0] = a; seen_doubles[1] = b; seen_doubles[2] = c; seen_doubles[3] = d; \
        seen_doubles[4] = e; seen_doubles[5] = f; seen_doubles[6] = g; \
        seen_floats = value; seen_float_tail = tail; OBSERVE(PREFIX, floats); \
        return a == 1 && b == 2 && c == 3 && d == 4 && e == 5 && f == 6 && g == 7 && \
            value.first == 1.25f && value.second == 2.5f && value.third == 4.75f && tail == -8.5f; \
    }
PROFILE(base, "aapcs")
PROFILE(vfp, "aapcs-vfp")

#define CHECK(PREFIX) \
    failed |= PREFIX##_pair(7, 11, 13, input_pair, -41) != 1; \
    failed |= PREFIX##_aligned(7, 11, 13, input_aligned, -41) != 1; \
    failed |= PREFIX##_packed(7, 11, 13, input_packed, -41) != 1; \
    failed |= PREFIX##_bytes(7, 11, 13, input_bytes, -41) != 1; \
    failed |= PREFIX##_words(7, 11, 13, input_words, -41) != 1; \
    failed |= PREFIX##_mixed(7, 11, 13, input_mixed, -41) != 1; \
    failed |= PREFIX##_floats(1, 2, 3, 4, 5, 6, 7, input_floats, -8.5f) != 1;
int main(void)
{
    int failed = 0;
    CHECK(base)
    CHECK(vfp)
    return failed;
}
