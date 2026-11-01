namespace left {
struct Same { int member; };
}
namespace right {
struct Same { long other; };
}
namespace recovered {
class Counter {
public:
    int value;
    __attribute__((noinline)) int inspect_scope(int amount);
};
int Counter::inspect_scope(int amount) {
    static int visits = 0;
    ++visits;
    int shadow = 11;
    int result = 0;
    asm volatile(".globl scope_outer\nscope_outer: nop" : : "m"(shadow) : "memory");
    {
        int shadow = 23;
        asm volatile(".globl scope_inner\nscope_inner: nop" : : "m"(shadow) : "memory");
        result += shadow;
    }
    asm volatile(".globl scope_after\nscope_after: nop" : : "m"(shadow) : "memory");
    return result + shadow + value + amount + visits;
}
}
left::Same first_object = {5};
right::Same second_object = {9};
int main() {
    recovered::Counter counter = {7};
    return counter.inspect_scope(3) == 45 && first_object.member == 5 && second_object.other == 9 ? 0 : 1;
}
