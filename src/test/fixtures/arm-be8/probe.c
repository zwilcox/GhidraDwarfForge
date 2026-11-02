volatile unsigned be8_global = 0x11223344;

__attribute__((noinline)) unsigned be8_probe(unsigned value)
{
    return value + be8_global;
}
