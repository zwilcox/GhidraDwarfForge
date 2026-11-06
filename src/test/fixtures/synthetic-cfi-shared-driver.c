#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>

#if defined(__x86_64__)
#define WITNESS_REGISTER "r12"
#elif defined(__aarch64__)
#define WITNESS_REGISTER "x19"
#else
#error Unsupported reference fixture target
#endif

uintptr_t cfi_module_bias;

#ifndef CFI_ENTRY_NAME
#define CFI_ENTRY_NAME "cfi_main"
#endif

__attribute__((noinline)) void cfi_ready(void) {
    __asm__ volatile ("" ::: "memory");
}

int main(int argc, char **argv) {
    if (argc != 2) {
        return 10;
    }
    void *module = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!module) {
        return 11;
    }
    int (*entry)(void) = (int (*)(void)) dlsym(module, CFI_ENTRY_NAME);
    Dl_info info;
    if (!entry || !dladdr((void *) entry, &info)) {
        return 12;
    }
    cfi_module_bias = (uintptr_t) info.dli_fbase;
    register unsigned long witness __asm__(WITNESS_REGISTER) = 0x7391;
    __asm__ volatile ("" : "+r" (witness));
    cfi_ready();
    int result = entry();
    __asm__ volatile ("" : "+r" (witness));
    if (witness != 0x7391) {
        return 14;
    }
    return dlclose(module) == 0 ? result : 13;
}
