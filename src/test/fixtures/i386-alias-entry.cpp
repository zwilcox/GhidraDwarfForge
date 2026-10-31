/* Freestanding Linux i386 entry for the shared source-built alias fixture. */
extern "C" int main();

extern "C" __attribute__((noreturn)) void _start() {
    int result = main();
    __asm__ volatile("int $0x80" : : "a"(1), "b"(result) : "memory");
    __builtin_unreachable();
}
