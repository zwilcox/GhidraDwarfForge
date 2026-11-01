/* Explicit lexical visibility is independent of proven initialization. */
#ifdef FORGE_LEXICAL_CALLS
__attribute__((noinline, noclone, optimize("omit-frame-pointer"))) void lexical_leaf(void)
{
    volatile int scratch = 909;
    __asm__ volatile("" : "+m"(scratch));
}
#define INSPECTED_CALL(block) \
    __asm__ volatile(".globl " #block "_call\n" #block "_call:\nnop" ::: "memory"); \
    lexical_leaf(); \
    __asm__ volatile(".globl " #block "_returned\n" #block "_returned:\nnop" ::: "memory");
#else
#define INSPECTED_CALL(block)
#endif

__attribute__((noinline, noclone)) int scoped(void)
{
    int sum = 0;
    __asm__ volatile(".globl outer_begin\nouter_begin:\nnop" ::: "memory");
    int shadow = 11;
    __asm__ volatile(".globl outer_live\nouter_live:\nnop" : "+m"(shadow));
    INSPECTED_CALL(outer)
    sum = shadow;
    {
        __asm__ volatile(".globl inner_begin\ninner_begin:\nnop" ::: "memory");
        int shadow = 23;
        __asm__ volatile(".globl inner_live\ninner_live:\nnop" : "+m"(shadow));
        INSPECTED_CALL(inner)
#ifdef FORGE_LEXICAL_GAP
        /* Analyst visibility may exclude this formatting-only marker while
         * the compiler's source block and the physical value remain intact. */
        __asm__ volatile(".globl inner_gap_begin\ninner_gap_begin:\nnop\n"
            ".globl inner_gap_end\ninner_gap_end:\nnop" ::: "memory");
#endif
        sum += shadow;
    }
    __asm__ volatile(".globl inner_end\ninner_end:\nnop" ::: "memory");
    sum += shadow;
    __asm__ volatile(".globl outer_end\nouter_end:\nnop" ::: "memory");
    return sum;
}

int main(void)
{
    return scoped() != 45;
}
