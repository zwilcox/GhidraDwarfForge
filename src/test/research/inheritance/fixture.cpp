// Redistributable compiler reference; no recovered-class inference.
struct Base {
    int base = 11;
    virtual int value() { return base; }
};
struct Single : Base {
    int single = 47;
    int value() override { return base + single; }
};
struct Left {
    int left = 13;
    virtual int first() { return left; }
};
struct Right {
    int right = 17;
    virtual int second() { return right; }
};
struct Multiple : Left, Right {
    int multiple = 29;
    int first() override { return left + multiple; }
    int second() override { return right + multiple; }
};
struct VirtualBase {
    int root = 19;
    virtual int root_value() { return root; }
};
struct VirtualLeft : virtual VirtualBase {
    int left = 23;
    virtual int left_value() { return left; }
};
struct VirtualRight : virtual VirtualBase {
    int right = 31;
    virtual int right_value() { return right; }
};
struct Diamond : VirtualLeft, VirtualRight {
    int leaf = 37;
    int root_value() override { return root + leaf; }
    int left_value() override { return left + leaf; }
    int right_value() override { return right + leaf; }
};

struct Abstract {
    int abstract_value = 41;
    virtual int pure_value() = 0;
};
struct Concrete : Abstract {
    int extra = 43;
    int pure_value() override { return abstract_value + extra; }
};

Abstract *abstract_base;
Concrete *concrete_object;
Base *single_base;
Single *single_object;
Right *multiple_right;
Multiple *multiple_object;
VirtualBase *diamond_base;
VirtualRight *diamond_right;
Diamond *diamond_object;
VirtualLeft *virtual_left_object;
VirtualRight *virtual_right_object;

extern "C" __attribute__((noinline)) void inheritance_checkpoint() {
    asm volatile("" ::: "memory");
}

int main() {
    Concrete concrete;
    abstract_base = &concrete;
    concrete_object = &concrete;
    Single one;
    Multiple many;
    Diamond diamond;
    VirtualLeft standalone_left;
    VirtualRight standalone_right;
    single_base = &one;
    single_object = &one;
    multiple_right = &many;
    multiple_object = &many;
    diamond_base = &diamond;
    diamond_right = &diamond;
    diamond_object = &diamond;
    virtual_left_object = &standalone_left;
    virtual_right_object = &standalone_right;
    inheritance_checkpoint();
    return abstract_base->pure_value() != 84 || single_base->value() != 58 || multiple_right->second() != 46 ||
        diamond_base->root_value() != 56 || diamond_right->right_value() != 68 ||
        virtual_left_object->root_value() != 19 || virtual_right_object->root_value() != 19;
}
