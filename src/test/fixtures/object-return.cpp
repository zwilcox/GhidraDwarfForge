namespace recovered {
struct Result {
    long long first;
    long long second;
    long long third;
};
struct Counter {
    long long value;
    __attribute__((noinline)) Result inspect_result(long long amount) {
        asm volatile(".global object_return_live\nobject_return_live:" ::: "memory");
        return Result{value + amount, value - amount, value * amount};
    }
};
Counter object{7};
Result observed{};
}
extern "C" __attribute__((noinline)) long long ordinary_roles(
        recovered::Counter *receiver, recovered::Result *carrier, long long amount) {
    asm volatile(".global ordinary_roles_live\nordinary_roles_live:" ::: "memory");
    return receiver->value + carrier->first + amount;
}
int main() {
    recovered::observed = recovered::object.inspect_result(3);
    return recovered::observed.first == 10 && recovered::observed.second == 4 &&
        recovered::observed.third == 21 &&
        ordinary_roles(&recovered::object, &recovered::observed, 25) == 42 ? 0 : 1;
}
