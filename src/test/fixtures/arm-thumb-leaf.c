volatile int thumb_sink;

__attribute__((noinline)) int thumb_add(int left, int right)
{
    int sum = left + right;
    thumb_sink = sum;
    return sum;
}
