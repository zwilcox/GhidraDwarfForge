/* First linked, actually executed neighbor for decompiler failure isolation. */
__attribute__((noinline)) int aggregate_fixture_before(void)
{
    __asm__ volatile("nop" ::: "memory");
    return 17;
}
