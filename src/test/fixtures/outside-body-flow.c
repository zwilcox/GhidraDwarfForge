__attribute__((noinline)) int boundary(int unused, int value) {
#if defined(__x86_64__)
    __asm__ volatile(
        ".globl probe_copy_done\nprobe_copy_done:\njmp probe_hidden\n"
        ".globl probe_resume\nprobe_resume:\njmp probe_after\n"
        ".globl probe_hidden\nprobe_hidden:\nxor %%esi, %%esi\njmp probe_resume\n"
        ".globl probe_after\nprobe_after:\n"
        : : : "esi", "memory");
#elif defined(__aarch64__)
    __asm__ volatile(
        ".globl probe_copy_done\nprobe_copy_done:\nb probe_hidden\n"
        ".globl probe_resume\nprobe_resume:\nb probe_after\n"
        ".globl probe_hidden\nprobe_hidden:\nmov w1, wzr\nb probe_resume\n"
        ".globl probe_after\nprobe_after:\n"
        : : : "x1", "memory");
#else
#error unsupported outside-body-flow fixture target
#endif
    return value + 7;
}
int main(void) {
    return boundary(123, 19) == 26 && boundary(456, -19) == -12 ? 0 : 1;
}
