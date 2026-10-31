/* Compiler-correlated stack definitions across branches and loop iterations. */
#if FORGE_STACK_LOCAL_BITS == 64
typedef long long stack_value;
#else
typedef int stack_value;
#endif
#if defined(__x86_64__)
#define FIRST_REGISTER "r10"
#define SECOND_REGISTER "r11"
#define KILL_SEED __asm__ volatile("xor %%edi,%%edi" ::: "rdi", "cc")
#define HOLE_TEXT ".byte 0xcc,0xcc,0xcc"
#define JUMP_TEXT "jmp "
#elif defined(__aarch64__)
#define FIRST_REGISTER "x9"
#define SECOND_REGISTER "x10"
#define KILL_SEED __asm__ volatile("mov x0,xzr" ::: "x0")
#define HOLE_TEXT ".inst 0xd4200000"
#define JUMP_TEXT "b "
#else
#error Selected runtime profiles are x86-64 and AArch64.
#endif
#define MARK(function, marker) ".globl " #function "_" #marker "\n" #function "_" #marker ":\nnop"
#define POINT(function, marker) __asm__ volatile(MARK(function, marker) : "+m"(value))
#define SAVE(function, marker, reg) do { \
    register stack_value held __asm__(reg) = value; \
    __asm__ volatile(MARK(function, marker) : "+r"(held) : "m"(value) : "memory"); \
} while (0)
#define BEGIN(function) __attribute__((noinline, noclone)) void function(stack_value seed, int choice) { \
    stack_value value = -12345; \
    __asm__ volatile("nop" : "+m"(value));
#define DEFINE(function) value = seed; POINT(function, live); KILL_SEED
#define END(function) POINT(function, join); effect_sink = value; POINT(function, retired); }
volatile stack_value effect_sink;

BEGIN(flow_diamond)
    DEFINE(flow_diamond);
    if (choice) { SAVE(flow_diamond, left, FIRST_REGISTER); }
    else { SAVE(flow_diamond, right, SECOND_REGISTER); }
    END(flow_diamond)

BEGIN(flow_kill)
    DEFINE(flow_kill);
    if (choice) {
        SAVE(flow_kill, left, FIRST_REGISTER);
        ((unsigned char *)&value)[0] ^= 90;
        POINT(flow_kill, changed);
    }
    else { SAVE(flow_kill, right, SECOND_REGISTER); }
    END(flow_kill)

BEGIN(flow_bypass)
    if (choice) { DEFINE(flow_bypass); SAVE(flow_bypass, left, FIRST_REGISTER); }
    END(flow_bypass)

BEGIN(flow_loop)
    DEFINE(flow_loop);
    for (int count = 0; count < choice + 2; count++) {
        POINT(flow_loop, loop);
        SAVE(flow_loop, loaded, FIRST_REGISTER);
    }
    END(flow_loop)

BEGIN(flow_loop_kill)
    DEFINE(flow_loop_kill);
    for (int count = 0; count < choice + 2; count++) {
        POINT(flow_loop_kill, loop);
        SAVE(flow_loop_kill, loaded, FIRST_REGISTER);
        ((unsigned char *)&value)[0] ^= 90;
        POINT(flow_loop_kill, changed);
    }
    END(flow_loop_kill)

BEGIN(flow_redefine)
    register stack_value held __asm__(FIRST_REGISTER) = -23456;
    int count = 0;
    do {
        __asm__ volatile("" : "+r"(held));
        value = seed + count;
        __asm__ volatile(MARK(flow_redefine, live) : "+r"(held), "+m"(value));
        held = value;
        __asm__ volatile(MARK(flow_redefine, loaded) : "+r"(held) : "m"(value) : "memory");
    } while (++count < choice + 2);
    END(flow_redefine)

BEGIN(flow_split)
    DEFINE(flow_split);
    __asm__ volatile(JUMP_TEXT "flow_split_afterhole\n"
        ".globl flow_split_hole\nflow_split_hole:\n" HOLE_TEXT "\n"
        ".globl flow_split_afterhole\nflow_split_afterhole:\nnop" ::: "memory");
    SAVE(flow_split, loaded, FIRST_REGISTER);
    END(flow_split)

__attribute__((noinline, noclone)) void navigation_control(void)
{
    effect_sink += 1;
    effect_sink -= 1;
    __asm__ volatile("nop" ::: "memory");
}

/* LLVM 18's call-site verifier repeats Die.getParent() when traversing a
 * lexical block. Keep the test driver unoptimized to avoid that compiler
 * call-site shape; all functions under test still use the command-line -O2. */
__attribute__((optimize("O0"))) int main(void)
{
    stack_value values[] = {19, -19,
#if FORGE_STACK_LOCAL_BITS == 64
        -81985529216486895LL
#else
        -1985229329
#endif
    };
    for (int index = 0; index < 3; index++) {
        stack_value seed = values[index];
        for (int choice = 0; choice < 2; choice++) {
            flow_diamond(seed, choice);
            if (effect_sink != seed) return 1;
            flow_kill(seed, choice);
            if (effect_sink != (choice ? (seed ^ 90) : seed)) return 2;
            flow_bypass(seed, choice);
            if (effect_sink != (choice ? seed : -12345)) return 3;
            flow_loop(seed, choice);
            if (effect_sink != seed) return 4;
            flow_loop_kill(seed, choice);
            if (effect_sink != ((choice & 1) ? (seed ^ 90) : seed)) return 5;
            flow_redefine(seed, choice);
            if (effect_sink != seed + choice + 1) return 6;
            flow_split(seed, choice);
            if (effect_sink != seed) return 7;
        }
    }
    navigation_control();
    return 0;
}
