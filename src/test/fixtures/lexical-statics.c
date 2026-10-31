/* Distinct static storage with nested and sibling lexical shadowing. */
int shadow = 101;

__attribute__((noinline, noclone)) int scoped_statics(void)
{
    static int shadow = 11;
    __asm__ volatile(".globl root_live\nroot_live:\nnop" ::: "memory");
    int sum = shadow;
    {
        static int shadow = 21;
        __asm__ volatile(".globl outer_begin\nouter_begin:\nnop" ::: "memory");
        sum += shadow;
        {
            static int shadow = 31;
            __asm__ volatile(".globl inner_begin\ninner_begin:\nnop" ::: "memory");
            sum += shadow;
        }
        __asm__ volatile(".globl inner_end\ninner_end:\nnop" ::: "memory");
        sum += shadow;
    }
    __asm__ volatile(".globl outer_end\nouter_end:\nnop" ::: "memory");
    sum += shadow;
    {
        static int shadow = 41;
        __asm__ volatile(".globl sibling_begin\nsibling_begin:\nnop" ::: "memory");
        sum += shadow;
    }
    __asm__ volatile(".globl sibling_end\nsibling_end:\nnop" ::: "memory");
    return sum + shadow;
}

__attribute__((noinline, noclone)) int other_statics(void)
{
    static int shadow = 51;
    __asm__ volatile(".globl other_live\nother_live:\nnop" ::: "memory");
    return shadow;
}

int main(void)
{
    int first = scoped_statics();
    int second = other_statics();
    __asm__ volatile(".globl global_live\nglobal_live:\nnop" ::: "memory");
    return first != 147 || second != 51 || shadow != 101;
}
