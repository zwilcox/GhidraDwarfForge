/* A compiler-inline instance and a distinct ordinary call for the P3.4 probe. */
volatile int inline_evidence_sink;

static __attribute__((always_inline)) inline int compiler_inline(int value)
{
    volatile int inline_local = value + 7;
    return inline_local * 3; /* INLINE_BREAK */
}

__attribute__((noinline, noclone)) int inline_caller(int value)
{
    int first = compiler_inline(value);
    int second = compiler_inline(value + 1);
    return first + second;
}

__attribute__((noinline, noclone)) int ordinary_callee(int value)
{
    return value * 5 + 2;
}

__attribute__((noinline, noclone)) int ordinary_caller(int value)
{
    int result = ordinary_callee(value);
    __asm__ volatile ("" : "+r" (result));
    return result + 1;
}

int main(void)
{
    inline_evidence_sink = inline_caller(4) + ordinary_caller(3);
    return inline_evidence_sink == 87 ? 0 : 1;
}
