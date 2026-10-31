/* Adjacent ARM/Thumb functions reached through volatile, tagged function pointers. */
namespace observed {
__attribute__((noinline, target("arm"))) int unique(int value) {
    static volatile int private_count = 7;
    return value + private_count;
}
__attribute__((noinline, target("thumb"))) int aliased(int value) {
    static volatile int private_count = 3;
    return value - private_count;
}
}
extern "C" __typeof__(observed::aliased) second_identity
    __attribute__((alias("_ZN8observed7aliasedEi"), copy(observed::aliased)));
static auto volatile unique_pointer = &observed::unique;
static auto volatile alias_pointer = &second_identity;
int main() {
    if (unique_pointer(19) != 26 || alias_pointer(19) != 16) return 1;
    if (unique_pointer(-19) != -12 || alias_pointer(-19) != -22) return 1;
    return 0;
}
