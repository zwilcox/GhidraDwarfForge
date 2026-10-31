/* Keep an old register copy alive while stores mutate or may alias a local. */
#if FORGE_STACK_LOCAL_BITS == 64
typedef long long stack_value;
#define INITIAL_VALUE (-81985529216486895LL)
#else
typedef int stack_value;
#define INITIAL_VALUE (-1985229329)
#endif

#if defined(__x86_64__)
#define BACKUP_REGISTER "r10"
#elif defined(__aarch64__)
#define BACKUP_REGISTER "x9"
#else
#error This runtime fixture requires a documented x86-64 or AArch64 profile.
#endif

volatile unsigned char *volatile effect_pointer;
volatile stack_value effect_sink;
volatile stack_value backup_sink;

#define MARKER(function, marker) ".globl " #function "_" #marker "\n" #function "_" #marker ":\nnop"
#define EFFECT_FUNCTION(function, effect) \
__attribute__((noinline, noclone)) void function(void) \
{ \
    stack_value value; \
    stack_value other = 37; \
    __asm__ volatile("nop" : "+m"(other)); \
    if ((effect) == 3) effect_pointer = (unsigned char *)&value; \
    if ((effect) == 4) effect_pointer = (unsigned char *)&other; \
    __asm__ volatile("" ::: "memory"); \
    value = INITIAL_VALUE; \
    __asm__ volatile(MARKER(function, live) : "+m"(value)); \
    register stack_value backup __asm__(BACKUP_REGISTER) = value; \
    __asm__ volatile(MARKER(function, before) : "+r"(backup) : "m"(value), "m"(other) : "memory"); \
    if ((effect) == 1) ((unsigned char *)&value)[0] ^= 90; \
    if ((effect) == 2) value = INITIAL_VALUE + 123; \
    if ((effect) == 3 || (effect) == 4) *effect_pointer ^= 90; \
    if ((effect) == 5) other = 127; \
    __asm__ volatile(MARKER(function, after) : "+r"(backup) : "m"(value), "m"(other) : "memory"); \
    effect_sink = value; \
    __asm__ volatile(MARKER(function, retired) : "+r"(backup)); \
    backup_sink = backup; \
}

EFFECT_FUNCTION(local_partial, 1)
EFFECT_FUNCTION(local_full, 2)
EFFECT_FUNCTION(local_unknown_alias, 3)
EFFECT_FUNCTION(local_unknown_other, 4)
EFFECT_FUNCTION(local_known_other, 5)

__attribute__((noinline, noclone)) void navigation_control(void)
{
    effect_sink += 1;
    effect_sink -= 1;
    __asm__ volatile("nop" ::: "memory");
}

int main(void)
{
    local_partial();
    if (effect_sink != (stack_value)(INITIAL_VALUE ^ 90) || backup_sink != INITIAL_VALUE) return 1;
    local_full();
    if (effect_sink != INITIAL_VALUE + 123 || backup_sink != INITIAL_VALUE) return 2;
    local_unknown_alias();
    if (effect_sink != (stack_value)(INITIAL_VALUE ^ 90) || backup_sink != INITIAL_VALUE) return 3;
    local_unknown_other();
    if (effect_sink != INITIAL_VALUE || backup_sink != INITIAL_VALUE) return 4;
    local_known_other();
    navigation_control();
    return effect_sink != INITIAL_VALUE || backup_sink != INITIAL_VALUE;
}
