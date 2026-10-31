/* Real compiler DWARF plus explicit machine boundaries for curated definitions. */
#if defined(__x86_64__)
#define HELD "r10"
#define COUNTER "r11"
#define MOVE32 "movl %k[value], %k[held]\n"
#define MOVE64 "movq %[value], %[held]\n"
#define WRITE32 "movl $909, %k[held]\n"
#define WRITE64 "movq $909, %[held]\n"
#define TEST "testl %k[choose], %k[choose]\n"
#define ZERO(name) "je " #name "_skipped\n"
#define JUMP(name, suffix) "jmp " #name "_" #suffix "\n"
#define COUNT "movl %k[choose], %%r11d\naddl $2, %%r11d\n"
#define AGAIN(name) "subl $1, %%r11d\njnz " #name "_loop\n"
#define GAP ".fill 8,1,0xcc\n"
#elif defined(__aarch64__)
#define HELD "x9"
#define COUNTER "x10"
#define MOVE32 "mov %w[held], %w[value]\n"
#define MOVE64 "mov %x[held], %x[value]\n"
#define WRITE32 "mov %w[held], #909\n"
#define WRITE64 "mov %x[held], #909\n"
#define TEST "cmp %w[choose], #0\n"
#define ZERO(name) "b.eq " #name "_skipped\n"
#define JUMP(name, suffix) "b " #name "_" #suffix "\n"
#define COUNT "add w10, %w[choose], #2\n"
#define AGAIN(name) "subs w10, w10, #1\nb.ne " #name "_loop\n"
#define GAP ".word 0xd4200000, 0xd4200000\n"
#else
#error Unsupported control-flow runtime target
#endif
#define LABEL(name, suffix) ".globl " #name "_" #suffix "\n" #name "_" #suffix ":\n"
#define DEFINE(name, move) LABEL(name, definition) move LABEL(name, ready) "nop\n"
#define KEEP(name, move, write) \
    DEFINE(name, move) TEST ZERO(name) \
    LABEL(name, taken) "nop\n" JUMP(name, join) \
    LABEL(name, skipped) "nop\n" LABEL(name, join) "nop\n"
#define KILL(name, move, write) \
    DEFINE(name, move) TEST ZERO(name) \
    LABEL(name, taken) "nop\n" LABEL(name, kill) write LABEL(name, after) "nop\n" JUMP(name, join) \
    LABEL(name, skipped) "nop\n" LABEL(name, join) "nop\n"
#define LOOP(name, move, write) \
    DEFINE(name, move) COUNT LABEL(name, loop) "nop\n" AGAIN(name) LABEL(name, join) "nop\n"
#define LOOPKILL(name, move, write) \
    DEFINE(name, move) COUNT LABEL(name, loop) "nop\n" LABEL(name, kill) write \
    LABEL(name, after) "nop\n" AGAIN(name) LABEL(name, join) "nop\n"
#define BYPASS(name, move, write) \
    TEST ZERO(name) DEFINE(name, move) JUMP(name, join) \
    LABEL(name, skipped) "nop\n" LABEL(name, join) "nop\n"
#define SPLIT(name, move, write) \
    DEFINE(name, move) LABEL(name, jump) JUMP(name, resume) \
    LABEL(name, gap) GAP LABEL(name, resume) "nop\n" LABEL(name, join) "nop\n"
#define FUNCTION(type, name, shape, move, write) \
    __attribute__((noinline, noclone)) type name(type input, int choose) { \
        register type held __asm__(HELD) = -12345; \
        __asm__ volatile(LABEL(name, before) "nop\n" : "+r"(held) : : "memory"); \
        __asm__ volatile(shape(name, move, write) \
            : [held] "+&r"(held) : [value] "r"(input + 7), [choose] "r"(choose) \
            : COUNTER, "cc", "memory"); \
        return held; \
    }
FUNCTION(int, flow_keep32, KEEP, MOVE32, WRITE32)
FUNCTION(long long, flow_keep64, KEEP, MOVE64, WRITE64)
FUNCTION(int, flow_kill32, KILL, MOVE32, WRITE32)
FUNCTION(long long, flow_kill64, KILL, MOVE64, WRITE64)
FUNCTION(int, flow_loop32, LOOP, MOVE32, WRITE32)
FUNCTION(long long, flow_loop64, LOOP, MOVE64, WRITE64)
FUNCTION(int, flow_loopkill32, LOOPKILL, MOVE32, WRITE32)
FUNCTION(long long, flow_loopkill64, LOOPKILL, MOVE64, WRITE64)
FUNCTION(int, flow_bypass32, BYPASS, MOVE32, WRITE32)
FUNCTION(long long, flow_bypass64, BYPASS, MOVE64, WRITE64)
FUNCTION(int, flow_split32, SPLIT, MOVE32, WRITE32)
FUNCTION(long long, flow_split64, SPLIT, MOVE64, WRITE64)
#define CHECK(name, input, choice, expected) if (name(input, choice) != (expected)) return 1;
#define ROUND(small, large) \
        CHECK(flow_keep32, small, choice, (small) + 7) \
        CHECK(flow_keep64, large, choice, (large) + 7) \
        CHECK(flow_kill32, small, choice, choice ? 909 : (small) + 7) \
        CHECK(flow_kill64, large, choice, choice ? 909 : (large) + 7) \
        CHECK(flow_loop32, small, choice, (small) + 7) \
        CHECK(flow_loop64, large, choice, (large) + 7) \
        CHECK(flow_loopkill32, small, choice, 909) \
        CHECK(flow_loopkill64, large, choice, 909) \
        CHECK(flow_bypass32, small, choice, choice ? (small) + 7 : -12345) \
        CHECK(flow_bypass64, large, choice, choice ? (large) + 7 : -12345) \
        CHECK(flow_split32, small, choice, (small) + 7) \
        CHECK(flow_split64, large, choice, (large) + 7)
__attribute__((noinline, noclone)) static int round_values(int small, long long large, int choice) {
    ROUND(small, large)
    return 0;
}
int main(void) {
    return round_values(19, 19LL, 0) || round_values(19, 19LL, 1) ||
        round_values(-19, -19LL, 0) || round_values(-19, -19LL, 1) ||
        round_values(-1985229329, -81985529216486895LL, 0) ||
        round_values(-1985229329, -81985529216486895LL, 1);
}
