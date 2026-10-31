/* Custom parameter and return ABIs: ordinary callers honor storage; GDB must not guess. */
volatile int sysv_calls;
volatile int microsoft_calls;
volatile int custom_return_calls;

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

/* The return is deliberately in EDX, with a deterministic wrong EAX value.
 * GCC's original DWARF cannot describe this custom ABI; the assembly caller
 * below and the explicit Ghidra return storage provide the behavioral oracle.
 */
__attribute__((naked, noinline))
int custom_return(int arg0)
{
    __asm__("addl $1, custom_return_calls(%rip)\n\t"
        "leal 7(%rdi), %edx\n\t"
        "movl $7, %eax\n\t"
        "ret");
}

__attribute__((noinline))
int invoke_custom_return(int value)
{
    int result;
    __asm__ volatile("call custom_return" : "=d"(result) : "D"(value)
        : "rax", "rcx", "rsi", "r8", "r9", "r10", "r11", "memory", "cc");
    return result;
}

int main(void)
{
    int first = sysv_function(1, 2, 3, 4);
    int second = microsoft_function(1, 2, 3, 4);
    int third = invoke_custom_return(1227);
    return first != 1234 || second != 1234 || third != 1234;
}
