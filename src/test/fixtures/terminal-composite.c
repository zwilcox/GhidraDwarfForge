/* Ordinary ARMv7 incoming pair with a declared whole-register overwrite. */
struct Pair { int low; int high; };
volatile int terminal_pair_low, terminal_pair_high;

__attribute__((noinline)) void terminal_pair(struct Pair pair)
{
    __asm__ volatile(".globl terminal_pair_before\nterminal_pair_before:\n\tnop\n" ::: "memory");
    terminal_pair_low = pair.low;
    terminal_pair_high = pair.high;
    __asm__ volatile(".globl terminal_pair_write\nterminal_pair_write:\n\tmov r0, #0\n" ::: "r0");
    __asm__ volatile(".globl terminal_pair_after\nterminal_pair_after:\n\tnop\n" ::: "memory");
}

int main(void)
{
    struct Pair pair = { -19, 37 };
    terminal_pair(pair);
    return terminal_pair_low != -19 || terminal_pair_high != 37;
}
