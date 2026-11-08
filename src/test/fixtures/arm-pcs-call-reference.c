volatile float seen_first, seen_second, base_result, vfp_result;

__attribute__((noinline, pcs("aapcs")))
float base_sum(float first, float second)
{
    seen_first = first;
    seen_second = second;
    return first + second;
}

__attribute__((noinline, pcs("aapcs-vfp")))
float vfp_sum(float first, float second)
{
    seen_first = first;
    seen_second = second;
    return first + second;
}

int main(void)
{
    base_result = base_sum(1.25f, 2.5f);
    vfp_result = vfp_sum(3.25f, 4.5f);
    return !(base_result == 3.75f && vfp_result == 7.75f);
}
