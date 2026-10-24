/* Compiler-backed direct-copy lifetimes. The incoming register is clobbered
 * after the compiler saves the parameter; the kill cases then change that
 * saved value, requiring Forge to stop describing the original parameter. */
#if defined(__x86_64__)
#define ORIGINAL_WRITE "xorw %%di, %%di\n"
#define ORIGINAL_CLOBBER "rdi", "cc"
#define BACKUP_WRITE "xorq %%rax, %%rax\n"
#define BACKUP_CLOBBER "rax", "cc"
#elif defined(__aarch64__)
#define ORIGINAL_WRITE "mov x0, xzr\n"
#define ORIGINAL_CLOBBER "x0"
#define BACKUP_WRITE "mov x1, xzr\n"
#define BACKUP_CLOBBER "x1"
#else
#error unsupported register-copy fixture target
#endif

#define LABEL(name, suffix) \
    ".globl " #name "_" #suffix "\n" #name "_" #suffix ":\n"

#define BODY(type, name) \
    volatile type name##_sink; \
    __attribute__((noinline, noclone)) type name(type value) \
    { \
        __asm__ volatile( \
            LABEL(name, saved) "nop\n" \
            LABEL(name, write) ORIGINAL_WRITE \
            : : "r"(value) : ORIGINAL_CLOBBER); \
        __asm__ volatile(LABEL(name, after) "nop\n" : : "r"(value)); \
        name##_sink = value;

#define KEEP(type, name) \
    BODY(type, name) \
        return value; \
    }

#define KILL(type, name) \
    BODY(type, name) \
        __asm__ volatile(LABEL(name, kill) BACKUP_WRITE : : : BACKUP_CLOBBER); \
        __asm__ volatile(LABEL(name, unavailable) "nop\n"); \
        return 0; \
    }

KEEP(int, copy32_keep)
KILL(int, copy32_kill)
KEEP(long long, copy64_keep)
KILL(long long, copy64_kill)

#define CHECK(name, input, result) \
    if (name(input) != (result) || name##_sink != (input)) { return 1; }

int main(void)
{
    CHECK(copy32_keep, 19, 19)
    CHECK(copy32_kill, 19, 0)
    CHECK(copy64_keep, 19, 19)
    CHECK(copy64_kill, 19, 0)
    CHECK(copy32_keep, -19, -19)
    CHECK(copy32_kill, -19, 0)
    CHECK(copy64_keep, -19, -19)
    CHECK(copy64_kill, -19, 0)
    CHECK(copy32_keep, -1985229329, -1985229329)
    CHECK(copy32_kill, -1985229329, 0)
    CHECK(copy64_keep, -81985529216486895LL, -81985529216486895LL)
    CHECK(copy64_kill, -81985529216486895LL, 0)
    return 0;
}
