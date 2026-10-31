/* Explicit nondefault ABI: ordinary calls work; unclassified debugger calls must not run. */
volatile int sysv_calls;
volatile int microsoft_calls;

__attribute__((noinline, sysv_abi))
int sysv_function(int arg0, int arg1, int arg2, int arg3)
{
    sysv_calls++;
    return arg0 * 1000 + arg1 * 100 + arg2 * 10 + arg3;
}

__attribute__((noinline, ms_abi))
int microsoft_function(int arg0, int arg1, int arg2, int arg3)
{
    microsoft_calls++;
    return arg0 * 1000 + arg1 * 100 + arg2 * 10 + arg3;
}

typedef int (*SysvPointer)(int, int, int, int);
typedef int (__attribute__((ms_abi)) *MicrosoftPointer)(int, int, int, int);
SysvPointer sysv_pointer = sysv_function;
MicrosoftPointer microsoft_pointer = microsoft_function;

int main(void)
{
    int first = sysv_function(1, 2, 3, 4);
    int second = microsoft_function(1, 2, 3, 4);
    return first != 1234 || second != 1234;
}
