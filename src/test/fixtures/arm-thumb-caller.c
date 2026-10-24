extern int thumb_add(int, int);
extern int arm_after(int);
extern volatile int thumb_sink;
typedef int (*binary_op)(int, int);
binary_op volatile thumb_pointer = thumb_add;

__attribute__((noinline)) int arm_call(int value)
{
    int direct = thumb_add(value, 7);
    int indirect = thumb_pointer(direct, 3);
    return indirect;
}

int main(void)
{
    int result = arm_call(12);
    return result == 22 && thumb_sink == 22 && arm_after(result) == 27 ? 0 : 1;
}
