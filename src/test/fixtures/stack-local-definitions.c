/* Distinct compiler objects reuse a stack slot. Curated definition starts
 * must expose only initialized values and retire earlier copies on reuse. */
volatile int scope_sink;
volatile int zero_sink;

__attribute__((noinline, noclone)) void stack_scope(void)
{
    __asm__ volatile("nop" ::: "memory");
    {
        int first = 11;
        __asm__ volatile(".globl first_live\nfirst_live:\nnop" : "+m"(first));
        scope_sink = first;
    }
    __asm__ volatile(".globl between_scopes\nbetween_scopes:\nnop" ::: "memory");
    {
        int second = 22;
        __asm__ volatile(".globl second_live\nsecond_live:\nnop" : "+m"(second));
        scope_sink = second;
    }
    __asm__ volatile(".globl after_scopes\nafter_scopes:\nnop" ::: "memory");
}

__attribute__((noinline, noclone)) void zero_stack(void)
{
    int zero = 37;
    __asm__ volatile(".globl zero_live\nzero_live:\nnop" : "+m"(zero));
    zero_sink = zero;
}

int main(void)
{
    stack_scope();
    zero_stack();
    return scope_sink != 22 || zero_sink != 37;
}
