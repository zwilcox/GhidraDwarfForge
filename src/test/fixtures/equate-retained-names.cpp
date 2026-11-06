__attribute__((noinline)) int retained_lookup(int input)
{
    return input + 7;
}

__attribute__((noinline)) int forge_equate_type_u64(int input)
{
    return input + 9;
}

int main()
{
    return retained_lookup(3) != 10 || forge_equate_type_u64(3) != 12;
}
