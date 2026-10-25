/* Ordinary ARM split register/stack parameter; compiler stack homes require the prologue. */
struct Pair { int low; int high; };
volatile int mixed_low, mixed_high;
#define MARK(name) __asm__ volatile(".global " #name "\n" #name ":\n" : : : "memory")
__attribute__((noinline)) void mixed(int a, int b, int c, struct Pair pair)
{
    MARK(mixed_before);
    mixed_low = pair.low;
    mixed_high = pair.high;
    MARK(mixed_after);
}
int main(void)
{
    struct Pair pair = {0x12345678, -1234567};
    mixed(1, 2, 3, pair);
    return mixed_low != pair.low || mixed_high != pair.high;
}
