#include <stddef.h>
#include <stdint.h>

enum operation {
    OP_ADD = 1,
    OP_XOR = 2
};

union word_view {
    uint32_t value;
    uint8_t bytes[4];
};

struct list_node {
    int value;
    struct list_node *next;
};

typedef int (*binary_operation)(int left, int right);

struct fixture_state {
    enum operation operation;
    union word_view word;
    int values[3];
    binary_operation apply;
};

volatile int fixture_sink;
volatile int scoped_counter = 7;

static __attribute__((always_inline)) inline void exercise_stack_depth_change(void) {
#if defined(__x86_64__)
    __asm__ volatile(
        ".globl forge_stack_normal\n\t"
        "forge_stack_normal:\n\t"
        "nop\n\t"
        "subq $16, %%rsp\n\t"
        ".globl forge_stack_changed\n\t"
        "forge_stack_changed:\n\t"
        "nop\n\t"
        "addq $16, %%rsp\n\t"
        ::: "memory");
#elif defined(__aarch64__)
    __asm__ volatile(
        ".globl forge_stack_normal\n\t"
        "forge_stack_normal:\n\t"
        "nop\n\t"
        "sub sp, sp, #16\n\t"
        ".globl forge_stack_changed\n\t"
        "forge_stack_changed:\n\t"
        "nop\n\t"
        "add sp, sp, #16\n\t"
        ::: "memory");
#elif defined(__mips__)
    __asm__ volatile(
        ".set push\n\t"
        ".set noreorder\n\t"
        ".globl forge_stack_normal\n\t"
        "forge_stack_normal:\n\t"
        "nop\n\t"
        "addiu $sp, $sp, -16\n\t"
        ".globl forge_stack_changed\n\t"
        "forge_stack_changed:\n\t"
        "nop\n\t"
        "addiu $sp, $sp, 16\n\t"
        ".set pop\n\t"
        ::: "memory");
#else
#error unsupported stack-depth fixture target
#endif
}

__attribute__((noinline))
int recovered_add(int left, int right, int unused, int register_seed) {
    (void)unused;
    (void)register_seed;
    int sum = left + right;
    fixture_sink = sum;
    exercise_stack_depth_change();
    return sum;
}

__attribute__((noinline))
int recovered_variadic(int count, ...) {
    fixture_sink = count;
    return count;
}

__attribute__((noinline))
void recovered_composite(int unused0, int unused1, uint32_t first,
        uint32_t second) {
    (void)unused0;
    (void)unused1;
    (void)first;
    (void)second;
    fixture_sink = 42;
}

__attribute__((noinline, noreturn, used))
void recovered_spin(int value) {
    fixture_sink = value;
    for (;;) {
    }
}

__attribute__((noinline))
static int recovered_xor(int left, int right) {
    int result = left ^ right;
    fixture_sink = result;
    return result;
}

__attribute__((noinline))
int walk_nodes(const struct list_node *node) {
    int total = 0;
    while (node != NULL) {
        total += node->value;
        node = node->next;
    }
    return total;
}

int main(void) {
    struct list_node tail = { 2, NULL };
    struct list_node head = { 1, &tail };
    struct fixture_state state = {
        OP_ADD,
        { .value = UINT32_C(0x11223344) },
        { 19, 23, 42 },
        recovered_xor
    };
    const int sum = recovered_add(state.values[0], state.values[1], 0, 31);
    const int mixed = state.apply(state.word.bytes[0], state.word.bytes[1]);
    const int variable_count = recovered_variadic(2, 19, 23);
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    recovered_composite(0, 0, UINT32_C(0x11223344), UINT32_C(0x55667788));
#else
    recovered_composite(0, 0, UINT32_C(0x55667788), UINT32_C(0x11223344));
#endif
    return sum == 42 && mixed != 0 && variable_count == 2 &&
        walk_nodes(&head) == 3 ? 0 : 1;
}
