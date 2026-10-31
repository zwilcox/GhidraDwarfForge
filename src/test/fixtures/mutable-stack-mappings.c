/* Saved analyst identity spans the compiler's stack value and working carrier. */
#if FORGE_STACK_LOCAL_BITS == 64
typedef long long stack_value;
#define INITIAL_VALUE (-81985529216486895LL)
#else
typedef int stack_value;
#define INITIAL_VALUE (-1985229329)
#endif
#if defined(__x86_64__)
#define CARRIER "r10"
#define COUNTER "r11"
#define TEST "testl %k[choice], %k[choice]\n"
#define SKIP(name) "je " #name "_changed\n"
#define COUNT "movl %k[choice], %%r11d\naddl $2, %%r11d\n"
#define AGAIN(name) "subl $1, %%r11d\njnz " #name "_update\n"
#if FORGE_STACK_LOCAL_BITS == 64
#define UPDATE "addq $5, %[work]\n"
#define SAVE "movq %[work], %[slot]\n"
#define LOAD "movq %[slot], %[work]\n"
#define KILL "movq $909, %[work]\n"
#else
#define UPDATE "addl $5, %k[work]\n"
#define SAVE "movl %k[work], %[slot]\n"
#define LOAD "movl %[slot], %k[work]\n"
#define KILL "movl $909, %k[work]\n"
#endif
#elif defined(__aarch64__)
#define CARRIER "x9"
#define COUNTER "x10"
#define TEST "cmp %w[choice], #0\n"
#define SKIP(name) "b.eq " #name "_changed\n"
#define COUNT "add w10, %w[choice], #2\n"
#define AGAIN(name) "subs w10, w10, #1\nb.ne " #name "_update\n"
#if FORGE_STACK_LOCAL_BITS == 64
#define UPDATE "add %x[work], %x[work], #5\n"
#define SAVE "str %x[work], %[slot]\n"
#define LOAD "ldr %x[work], %[slot]\n"
#define KILL "mov %x[work], #909\n"
#else
#define UPDATE "add %w[work], %w[work], #5\n"
#define SAVE "str %w[work], %[slot]\n"
#define LOAD "ldr %w[work], %[slot]\n"
#define KILL "mov %w[work], #909\n"
#endif
#else
#error Unsupported runtime target
#endif
#define LABEL(name, marker) ".globl " #name "_" #marker "\n" #name "_" #marker ":\n"
#define MARK(name, marker) LABEL(name, marker) "nop\n"
volatile int path_choice;
volatile stack_value effect_sink;
volatile stack_value backup_sink;
#define ONCE(name) LABEL(name, update) UPDATE MARK(name, updated)
#define BRANCH(name) TEST SKIP(name) ONCE(name)
#define LOOP(name) COUNT ONCE(name) AGAIN(name)
#define FUNCTION(name, saving, changes) \
__attribute__((noinline, noclone)) void name(void) { \
    stack_value value = -777; \
    __asm__ volatile(MARK(name, before) : "+m"(value)); \
    value = INITIAL_VALUE; \
    __asm__ volatile(MARK(name, live) : "+m"(value)); \
    register stack_value working __asm__(CARRIER); \
    __asm__ volatile(LABEL(name, load) LOAD : [work] "=r"(working) : [slot] "m"(value)); \
    __asm__ volatile(MARK(name, loaded) : "+r"(working) : "m"(value)); \
    __asm__ volatile(changes(name) MARK(name, changed) : [work] "+r"(working) : [choice] "r"(path_choice) : COUNTER, "cc"); \
    __asm__ volatile(LABEL(name, save) saving : [slot] "+m"(value) : [work] "r"(working) : "memory"); \
    __asm__ volatile(MARK(name, saved) : "+r"(working) : "m"(value)); \
    __asm__ volatile(LABEL(name, kill) KILL : [work] "=r"(working)); \
    __asm__ volatile(MARK(name, killed) : "+r"(working) : "m"(value)); \
    __asm__ volatile(LABEL(name, reload) LOAD : [work] "=r"(working) : [slot] "m"(value)); \
    __asm__ volatile(MARK(name, reloaded) : "+r"(working) : "m"(value)); \
    value = INITIAL_VALUE + 123; \
    __asm__ volatile(MARK(name, lost) : "+r"(working) : "m"(value) : "memory"); \
    effect_sink = value; \
    backup_sink = working; \
}
FUNCTION(mutable_saved, SAVE, ONCE)
FUNCTION(mutable_unsaved, "nop\n", ONCE)
FUNCTION(mutable_branch, SAVE, BRANCH)
FUNCTION(mutable_loop, SAVE, LOOP)
FUNCTION(mutable_conflict, SAVE, ONCE)
__attribute__((noinline, noclone)) void navigation_control(void) {
    effect_sink += 1;
    effect_sink -= 1;
    __asm__ volatile("nop" ::: "memory");
}
int main(void) {
    mutable_saved();
    if (effect_sink != INITIAL_VALUE + 123 || backup_sink != INITIAL_VALUE + 5) return 1;
    mutable_unsaved();
    if (effect_sink != INITIAL_VALUE + 123 || backup_sink != INITIAL_VALUE) return 2;
    path_choice = 0;
    mutable_branch();
    if (effect_sink != INITIAL_VALUE + 123 || backup_sink != INITIAL_VALUE) return 3;
    path_choice = 1;
    mutable_branch();
    if (effect_sink != INITIAL_VALUE + 123 || backup_sink != INITIAL_VALUE + 5) return 4;
    path_choice = 0;
    mutable_loop();
    if (effect_sink != INITIAL_VALUE + 123 || backup_sink != INITIAL_VALUE + 10) return 5;
    path_choice = 1;
    mutable_loop();
    if (effect_sink != INITIAL_VALUE + 123 || backup_sink != INITIAL_VALUE + 15) return 6;
    mutable_conflict();
    navigation_control();
    return effect_sink != INITIAL_VALUE + 123 || backup_sink != INITIAL_VALUE + 5;
}
