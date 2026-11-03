#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stdint.h>
#include <stdlib.h>

/* Independent runtime oracle supplied by the target's dynamic linker. */
volatile uintptr_t fixture_loader_bias;
volatile uintptr_t fixture_loader_other_bias;

__attribute__((noinline)) void fixture_after_load(void) {
    __asm__ volatile ("" ::: "memory");
}
__attribute__((noinline)) void fixture_select_other(void) {
    __asm__ volatile ("" ::: "memory");
}
__attribute__((noinline)) void fixture_after_unload(void) {
    __asm__ volatile ("" ::: "memory");
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    int ambiguous = argv[2][0] == 'a';
    for (int iteration = 0; iteration < 2; iteration++) {
        void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
        struct link_map *map;
        if (!handle || dlinfo(handle, RTLD_DI_LINKMAP, &map)) return 3;
        fixture_loader_bias = (uintptr_t)map->l_addr;
        void *other = NULL;
        if (ambiguous) {
            other = dlmopen(LM_ID_NEWLM, argv[1], RTLD_NOW | RTLD_LOCAL);
            if (!other || dlinfo(other, RTLD_DI_LINKMAP, &map)) return 4;
            fixture_loader_other_bias = (uintptr_t)map->l_addr;
        }
        int (*function)(int, int, int, int) = dlsym(handle, "recovered_add");
        if (!function) return 5;
        fixture_after_load();
        if (function(19, 23, 0, 31) != 42) return 6;
        if (other) {
            function = dlsym(other, "recovered_add");
            if (!function) return 7;
            fixture_select_other();
            if (function(-19, 42, 0, 31) != 23) return 8;
        }
        if (dlclose(handle) || (other && dlclose(other))) return 9;
        fixture_after_unload();
    }
    return 0;
}
