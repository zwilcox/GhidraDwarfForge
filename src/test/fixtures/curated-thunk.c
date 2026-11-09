/* A small tail-transfer body whose decompiler may substitute its destination. */
__attribute__((noinline, noclone)) int implementation(int value)
{
    return value * 2 + 1;
}

__attribute__((noinline, noclone)) int gateway(int value)
{
    /* Keep a real instruction boundary after the entry-only location. */
    __asm__ volatile("nop");
    return implementation(value);
}

int main(void)
{
    return gateway(19) != 39;
}
