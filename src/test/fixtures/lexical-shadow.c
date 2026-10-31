/* Explicit lexical visibility is independent of proven initialization. */
__attribute__((noinline, noclone)) int scoped(void)
{
    int sum = 0;
    __asm__ volatile(".globl outer_begin\nouter_begin:\nnop" ::: "memory");
    int shadow = 11;
    __asm__ volatile(".globl outer_live\nouter_live:\nnop" : "+m"(shadow));
    sum = shadow;
    {
        __asm__ volatile(".globl inner_begin\ninner_begin:\nnop" ::: "memory");
        int shadow = 23;
        __asm__ volatile(".globl inner_live\ninner_live:\nnop" : "+m"(shadow));
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
