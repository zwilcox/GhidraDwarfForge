/* Addressable incoming parameters survive a real register clobber on stack.
 * A later unrelated-looking memory write conservatively ends Forge's proof. */
#if defined(__x86_64__)
#define ORIGINAL_WRITE "xor %%edi, %%edi\n"
#define ORIGINAL_CLOBBER "rdi", "cc"
#elif defined(__aarch64__)
#define ORIGINAL_WRITE "mov x0, xzr\n"
#define ORIGINAL_CLOBBER "x0"
#else
#error unsupported stack-spill fixture target
#endif

#define LABEL(name, suffix) \
    ".globl " #name "_" #suffix "\n" #name "_" #suffix ":\n"

#define BODY(type, name) \
    volatile type name##_sink; \
    __attribute__((noinline, noclone)) type name(type value) \
    { \
        __asm__ volatile(LABEL(name, saved) "nop\n" LABEL(name, write) ORIGINAL_WRITE \
            : : "m"(value) : ORIGINAL_CLOBBER); \
        __asm__ volatile(LABEL(name, after) "nop\n" : : "m"(value));

#define KEEP(type, name) \
    BODY(type, name) \
        return value; \
    }

#define KILL(type, name) \
    BODY(type, name) \
        name##_sink = value; \
        __asm__ volatile(LABEL(name, unavailable) "nop\n" : : "m"(value)); \
        return value; \
    }

KEEP(int, spill32_keep)
KILL(int, spill32_kill)
KEEP(long long, spill64_keep)
KILL(long long, spill64_kill)

#define CHECK(name, input) \
    if (name(input) != (input)) { return 1; }
#define ROUND(small, large) \
    CHECK(spill32_keep, small) \
    CHECK(spill32_kill, small) \
    CHECK(spill64_keep, large) \
    CHECK(spill64_kill, large) \
    if (spill32_kill_sink != (small) || spill64_kill_sink != (large)) { return 1; }

int main(void)
{
    ROUND(19, 19)
    ROUND(-19, -19)
    ROUND(-1985229329, -81985529216486895LL)
    return 0;
}
