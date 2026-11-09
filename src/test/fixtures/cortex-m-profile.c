/* Redistributable bare-metal Cortex-M3 fixture; no vendor runtime required. */
typedef unsigned int u32;

volatile int cortex_initialized = 7;
volatile int cortex_bss_counter;
volatile int cortex_result;
volatile u32 cortex_exception_count;
volatile u32 cortex_exception_return;
volatile u32 cortex_exception_number;
volatile u32 cortex_stacked_address;
volatile u32 cortex_stacked_pc;
volatile u32 cortex_stacked_xpsr;

__attribute__((noinline)) int cortex_compute(int input)
{
    volatile int local = input + cortex_initialized;
    cortex_bss_counter += local;
    __asm__ volatile(".global cortex_compute_probe\ncortex_compute_probe:" ::: "memory");
    return local + 3;
}

int (*volatile cortex_function_pointer)(int) = cortex_compute;

/* Assembly passes the hardware frame, EXC_RETURN and IPSR without changing LR. */
__attribute__((noinline)) void cortex_svc_body(u32 *frame, u32 exception_return, u32 number)
{
    cortex_exception_count++;
    cortex_exception_return = exception_return;
    cortex_exception_number = number;
    cortex_stacked_address = (u32)frame;
    cortex_stacked_pc = frame[6];
    cortex_stacked_xpsr = frame[7];
    __asm__ volatile(".global cortex_exception_probe\ncortex_exception_probe:" ::: "memory");
}

__attribute__((noreturn)) void cortex_psp_entry(void);

__attribute__((noreturn, noinline)) void cortex_psp_main(void)
{
    cortex_result = cortex_function_pointer(11);
    __asm__ volatile("svc #2\n.global cortex_after_svc_psp\ncortex_after_svc_psp:" ::: "memory");
    __asm__ volatile(".global cortex_done\ncortex_done:" ::: "memory");
    for (;;) {
        __asm__ volatile("nop");
    }
}

__attribute__((noreturn, noinline)) void cortex_main(void)
{
    cortex_bss_counter = 1;
    cortex_result = cortex_function_pointer(9);
    __asm__ volatile("svc #1\n.global cortex_after_svc_msp\ncortex_after_svc_msp:" ::: "memory");
    cortex_psp_entry();
}
