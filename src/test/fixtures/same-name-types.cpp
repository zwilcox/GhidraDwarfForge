/* Distinct compiler identities; the analyst fixture also renames category types. */
namespace alpha {
enum State { SHARED = 1, ALPHA_READY = 5 };
struct Node {
    int value;
    Node *next;
    __attribute__((noinline)) int inspect(int amount) {
        asm volatile(".global alpha_live\nalpha_live:" ::: "memory");
        return value + amount;
    }
};
typedef Node Record;
Record object{7, nullptr};
State state = ALPHA_READY;
}

namespace beta {
enum State { SHARED = 2, BETA_READY = 17 };
struct Node {
    long long value;
    Node *next;
    int extra;
    __attribute__((noinline)) int inspect(int amount) {
        asm volatile(".global beta_live\nbeta_live:" ::: "memory");
        return static_cast<int>(value) + extra + amount;
    }
};
typedef Node Record;
Record object{101, nullptr, 13};
State state = BETA_READY;
}

struct CategorySmall { int code; };
struct CategoryLarge { long long code; int extra; };
typedef CategorySmall SmallHandle;
typedef CategoryLarge LargeHandle;
SmallHandle category_small{23};
LargeHandle category_large{0x112233445566LL, 31};

int main() {
    alpha::object.next = &alpha::object;
    beta::object.next = &beta::object;
    return alpha::object.inspect(3) == 10 && beta::object.inspect(5) == 119 &&
        category_small.code == 23 && category_large.extra == 31 ? 0 : 1;
}
