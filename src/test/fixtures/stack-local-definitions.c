/* Distinct compiler objects reuse a stack slot. Curated definition starts
 * must expose only initialized values and retire earlier copies on reuse. */
#if FORGE_STACK_LOCAL_BITS == 64
typedef long long stack_value;
#define FIRST_VALUE (-81985529216486895LL)
#define SECOND_VALUE 81985529216486895LL
#else
typedef int stack_value;
#define FIRST_VALUE (-1985229329)
#define SECOND_VALUE 305419896
#endif

volatile stack_value scope_sink;
volatile stack_value zero_sink;

__attribute__((noinline, noclone)) void stack_scope(void)
{
    __asm__ volatile("nop" ::: "memory");
    {
        stack_value first = FIRST_VALUE;
        __asm__ volatile(".globl first_live\nfirst_live:\nnop" : "+m"(first));
        scope_sink = first;
    }
    __asm__ volatile(".globl between_scopes\nbetween_scopes:\nnop" ::: "memory");
    {
        stack_value second = SECOND_VALUE;
        __asm__ volatile(".globl second_live\nsecond_live:\nnop" : "+m"(second));
        scope_sink = second;
    }
    __asm__ volatile(".globl after_scopes\nafter_scopes:\nnop" ::: "memory");
}

__attribute__((noinline, noclone)) void zero_stack(void)
{
    stack_value zero = 37;
    __asm__ volatile(".globl zero_live\nzero_live:\nnop" : "+m"(zero));
    zero_sink = zero;
}

int main(void)
{
    stack_scope();
    zero_stack();
    return scope_sink != SECOND_VALUE || zero_sink != 37;
}
