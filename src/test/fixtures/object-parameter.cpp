namespace recovered {
struct Counter {
    int value;
    __attribute__((noinline)) int inspect_object(int amount) {
        asm volatile(".global object_live\nobject_live:" ::: "memory");
        return value + amount;
    }
};
}

extern "C" __attribute__((noinline)) int ordinary_object(int value) {
    asm volatile(".global ordinary_live\nordinary_live:" ::: "memory");
    return value + 1;
}

int main() {
    recovered::Counter object{7};
    return object.inspect_object(3) == 10 && ordinary_object(41) == 42 ? 0 : 1;
}
