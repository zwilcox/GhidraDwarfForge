/* Ordinary source-built dynamic integer parameters; no assembly or custom ABI. */
volatile int dynamic_first, dynamic_second, dynamic_before, dynamic_after;

__attribute__((noinline)) void dynamic_keep(int first, int second)
{
    dynamic_first = first;
    dynamic_second = second;
}

__attribute__((noinline)) int dynamic_change(int first, int second)
{
    dynamic_before = first;
    first += second;
    dynamic_after = first;
    return first;
}

int main(void)
{
    dynamic_keep(-19, 37);
    int result = dynamic_change(-11, 5);
    return !(dynamic_first == -19 && dynamic_second == 37 &&
        dynamic_before == -11 && dynamic_after == -6 && result == -6);
}
