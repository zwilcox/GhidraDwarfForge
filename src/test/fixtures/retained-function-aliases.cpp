/* Real ELF aliases and per-function objects. Curated names are applied in Ghidra. */
namespace observed {
__attribute__((noinline)) int unique(int value) {
    static volatile int private_count = 7;
    return value + private_count;
}
__attribute__((noinline)) int aliased(int value) {
    static volatile int private_count = 3;
    return value - private_count;
}
}
extern "C" int second_identity(int) __attribute__((alias("_ZN8observed7aliasedEi")));
int main() {
    if (observed::unique(19) != 26 || second_identity(19) != 16) return 1;
    if (observed::unique(-19) != -12 || second_identity(-19) != -22) return 1;
    return 0;
}
