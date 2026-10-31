namespace observed {
__attribute__((noinline)) int combine(int value)
{
    return value + 7;
}
__attribute__((noinline)) double combine(double value)
{
    return value - 0.5;
}
}
volatile int integer_result;
volatile double floating_result;
int main()
{
    integer_result = observed::combine(19);
    floating_result = observed::combine(19.0);
    if (integer_result != 26 || floating_result != 18.5) return 1;
    integer_result = observed::combine(-19);
    floating_result = observed::combine(-19.0);
    return integer_result != -12 || floating_result != -19.5;
}
