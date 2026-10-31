/* Actual direct-call graphs; the caller's full-width saved carriers are untouched. */
volatile int inspected_visits;
volatile int inspected_branch;
__attribute__((noinline, noclone)) int inspected_leaf(int value)
{
    inspected_visits++;
    return value & 255;
}
__attribute__((noinline, noclone)) int inspected_branching(int value)
{
    if (value & 2) {
        __asm__ volatile("nop" ::: "memory");
        inspected_branch = -1;
    }
    else {
        __asm__ volatile("nop\nnop" ::: "memory");
        inspected_branch = 1;
    }
    inspected_visits++;
    return value & 255;
}
__attribute__((noinline, noclone)) int inspected_loop(int value)
{
    for (int count = 0; count < (value & 3) + 2; count++) {
        __asm__ volatile("nop" ::: "memory");
        inspected_visits++;
    }
    return value & 255;
}
__attribute__((noinline, noclone)) int inspected_nested(int value)
{
    int result = inspected_branching(value);
    __asm__ volatile("nop" : "+r"(result) : : "memory");
    return result + 1;
}
__attribute__((noinline, noclone)) int inspected_recursive(int value)
{
    inspected_visits++;
    // Keep the recursive call at function scope: LLVM 18's call-site verifier
    // loops on a call-site DIE nested inside a lexical block.
    if (value <= 0) return 0;
    int result = inspected_recursive(value - 1);
    __asm__ volatile("nop" : "+r"(result) : : "memory");
    return result + 1;
}
__attribute__((noinline, noclone)) int inspected_split(int value)
{
    inspected_visits++;
#if defined(__x86_64__)
    __asm__ volatile("jmp inspected_split_afterhole\n"
        ".globl inspected_split_hole\ninspected_split_hole:\n.byte 0xcc,0xcc,0xcc\n"
        ".globl inspected_split_afterhole\ninspected_split_afterhole:\nnop" ::: "memory");
#elif defined(__aarch64__)
    __asm__ volatile("b inspected_split_afterhole\n"
        ".globl inspected_split_hole\ninspected_split_hole:\n.inst 0xd4200000\n"
        ".globl inspected_split_afterhole\ninspected_split_afterhole:\nnop" ::: "memory");
#endif
    return value & 255;
}
/* ABI metadata alone must not erase an observed write, even if this compiler
 * saves/restores the register. Inspect both the writing and non-writing path. */
__attribute__((noinline, noclone)) int inspected_clobber(int value)
{
    inspected_visits++;
    if (value & 2) {
#if defined(__x86_64__)
        __asm__ volatile("xorq %%rbx,%%rbx" ::: "rbx", "cc");
#elif defined(__aarch64__)
        __asm__ volatile("mov x19,xzr" ::: "x19");
#endif
        inspected_branch = -1;
    }
    else inspected_branch = 1;
    return value & 255;
}
