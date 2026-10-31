/* Complete register copies of the incoming value; optional repeated reuse. */
#if defined(__x86_64__)
#define FIRST "r10"
#define SELF32 "mov %0,%0\n"
#define SELF64 SELF32
#define SECOND "r11"
#define ORIGINAL_WRITE "xorq %%rdi, %%rdi\n"
#define ORIGINAL_CLOBBER "rdi", "cc"
#define FIRST_WRITE "xorq %%r10, %%r10\n"
#define FIRST_CLOBBER "r10", "cc"
#define SECOND_WRITE "xorq %%r11, %%r11\n"
#define SECOND_CLOBBER "r11", "cc"
#elif defined(__aarch64__)
#define FIRST "x9"
#define SELF32 "mov %w0,%w0\n"
#define SELF64 "mov %0,%0\n"
#define SECOND "x10"
#define ORIGINAL_WRITE "mov x0, xzr\n"
#define ORIGINAL_CLOBBER "x0"
#define FIRST_WRITE "mov x9, xzr\n"
#define FIRST_CLOBBER "x9"
#define SECOND_WRITE "mov x10, xzr\n"
#define SECOND_CLOBBER "x10"
#else
#error Unsupported second-copy fixture target
#endif
#define LABEL(name, suffix) \
    ".globl " #name "_" #suffix "\n" #name "_" #suffix ":\n"
#ifdef COPY_CHAIN
#define EXTRA_COPIES(type, name) \
        __asm__ volatile(LABEL(name, copy3) : "+r"(second) : : "memory"); \
        register type third __asm__(FIRST) = second; \
        __asm__ volatile(LABEL(name, third) "nop\n" \
            LABEL(name, kill2) SECOND_WRITE \
            LABEL(name, tail3) "nop\n" : "+r"(third) : : SECOND_CLOBBER, "memory"); \
        __asm__ volatile(LABEL(name, copy4) : "+r"(third) : : "memory"); \
        register type fourth __asm__(SECOND) = third; \
        __asm__ volatile(LABEL(name, fourth) "nop\n" \
            LABEL(name, kill3) FIRST_WRITE \
            LABEL(name, tail4) "nop\n" : "+r"(fourth) : : FIRST_CLOBBER, "memory");
#define FINAL_VALUE fourth
#else
#define EXTRA_COPIES(type, name)
#define FINAL_VALUE second
#endif
#ifdef COPY_SELF
#define SELF(type, name, instruction) __asm__ volatile(instruction : "+r"(first));
#else
#define SELF(type, name, instruction)
#endif
#ifdef COPY_EARLY
#define FIRST_TWO(type, name, instruction) \
        register type first __asm__(FIRST) = value; \
        __asm__ volatile(LABEL(name, saved) "nop\n" \
            LABEL(name, copy) : "+r"(first) : : "memory"); \
        register type second __asm__(SECOND) = first; \
        __asm__ volatile(LABEL(name, second) "nop\n" \
            LABEL(name, write) ORIGINAL_WRITE : "+r"(second), "+r"(first) : : ORIGINAL_CLOBBER, "memory"); \
        __asm__ volatile(LABEL(name, after) "nop\n" : "+r"(second), "+r"(first) : : "memory"); \
        __asm__ volatile(LABEL(name, kill) FIRST_WRITE \
            LABEL(name, tail) "nop\n" : "+r"(second) : : FIRST_CLOBBER, "memory");
#else
#define FIRST_TWO(type, name, instruction) \
        register type first __asm__(FIRST) = value; \
        __asm__ volatile(LABEL(name, saved) "nop\n" \
            LABEL(name, write) ORIGINAL_WRITE : "+r"(first) : : ORIGINAL_CLOBBER, "memory"); \
        __asm__ volatile(LABEL(name, after) "nop\n" \
            LABEL(name, copy) : "+r"(first) : : "memory"); \
        register type second __asm__(SECOND) = first; \
        __asm__ volatile(LABEL(name, second) "nop\n" : "+r"(second), "+r"(first) : : "memory"); \
        SELF(type, name, instruction) \
        __asm__ volatile(LABEL(name, kill) FIRST_WRITE \
            LABEL(name, tail) "nop\n" : "+r"(second) : : FIRST_CLOBBER, "memory");
#endif
#define BODY(type, name, instruction) \
    volatile type name##_sink; \
    __attribute__((noinline, noclone)) type name(type value) { \
        FIRST_TWO(type, name, instruction) \
        EXTRA_COPIES(type, name) \
        name##_sink = FINAL_VALUE; \
        __asm__ volatile(LABEL(name, erase) SECOND_WRITE \
            LABEL(name, unavailable) "nop\n" : : : SECOND_CLOBBER, "memory"); \
        return 0; \
    }
BODY(int, chain32, SELF32)
BODY(long long, chain64, SELF64)
#define CHECK(name, value) if (name(value) != 0 || name##_sink != (value)) return 1;
int main(void) {
    CHECK(chain32, 19)
    CHECK(chain64, 19)
    CHECK(chain32, -19)
    CHECK(chain64, -19)
    CHECK(chain32, -1985229329)
    CHECK(chain64, -81985529216486895LL)
    return 0;
}
