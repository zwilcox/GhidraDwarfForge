#include <stdarg.h>
#include <stdlib.h>

volatile int variadic_calls;

__attribute__((noinline)) int known_variadic(int count, ...)
{
    va_list arguments;
    va_start(arguments, count);
    int sum = 0;
    for (int i = 0; i < count; i++) {
        sum += va_arg(arguments, int);
    }
    va_end(arguments);
    variadic_calls++;
    return sum;
}

__attribute__((noinline, noreturn)) void known_noreturn(int code)
{
    _Exit(code);
}

int (*variadic_pointer)(int, ...) = known_variadic;
void (*noreturn_pointer)(int) = known_noreturn;

int main(void)
{
    int value = variadic_pointer(3, 10, 20, 30);
    noreturn_pointer(value != 60);
    return 127;
}
