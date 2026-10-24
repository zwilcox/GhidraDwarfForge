/* One hard-float ELF with explicit per-function base and VFP argument conventions. */
volatile float base_first, base_second, vfp_first, vfp_second, sum_value;

__attribute__((noinline, pcs("aapcs")))
void base_probe(float first, float second)
{
    base_first = first;
    base_second = second;
}

__attribute__((noinline, pcs("aapcs-vfp")))
void vfp_probe(float first, float second)
{
    vfp_first = first;
    vfp_second = second;
}

/* A real result write and ordinary ARM return retain the conservative tail case. */
__attribute__((noinline, pcs("aapcs-vfp")))
float vfp_sum(float first, float second)
{
    return first + second;
}

int main(void)
{
    base_probe(1.25f, 2.5f);
    vfp_probe(3.25f, 4.5f);
    sum_value = vfp_sum(6.25f, 7.5f);
    return !(base_first == 1.25f && base_second == 2.5f &&
        vfp_first == 3.25f && vfp_second == 4.5f && sum_value == 13.75f);
}
