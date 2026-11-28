/* Two observable storage locations with a compiler-visible transition. */
struct EvalNode {
    volatile struct EvalNode *next;
    int value;
};

volatile struct EvalNode eval_first = {&eval_first, 19};
volatile struct EvalNode eval_second = {&eval_first, -1};

#ifdef EVAL_X86_ASM
extern int eval_invoke(void);
#else
__attribute__((noinline)) int eval_probe(void)
{
    eval_second.value = eval_first.value + 23;
    __asm__ volatile (".globl eval_transition\neval_transition:" ::: "memory");
    return eval_second.value;
}
#endif

int main(void)
{
#ifdef EVAL_X86_ASM
    return eval_invoke() == 42 ? 0 : 1;
#else
    return eval_probe() == 42 ? 0 : 1;
#endif
}
