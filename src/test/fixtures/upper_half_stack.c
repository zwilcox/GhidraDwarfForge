extern int nonzero_main(void);
extern volatile int nonzero_sink;

/* SysV AMD64 passes the seventh integer argument at entry RSP + 8. */
__attribute__((noinline))
int kernel_stack_argument(int a, int b, int c, int d, int e, int f, int stack_value) {
    return stack_value;
}

__attribute__((section(".text.start"), noreturn))
void _start(void) {
    nonzero_sink = kernel_stack_argument(1, 2, 3, 4, 5, 6, nonzero_main());
    for (;;) { }
}
