/* Compiler reference for #117. No hand-authored call-site DWARF is supplied. */
#define KEEP __attribute__((noinline, noclone, noipa))

volatile int cs_sink;
volatile int cs_choice;

KEEP void cs_checkpoint(void)
{
    __asm__ volatile ("" ::: "memory");
}

KEEP int cs_leaf(int value)
{
    cs_sink = value;
    cs_checkpoint();
    return cs_sink + 1;
}

KEEP int cs_normal(int value)
{
    int result = cs_leaf(value + 1);
    cs_sink = result;
    return result + 1;
}

KEEP int cs_tail_middle(int value)
{
    return cs_leaf(value + 2);
}

KEEP int cs_tail_first(int value)
{
    return cs_tail_middle(value + 1);
}

KEEP int cs_left(int value)
{
    return cs_leaf(value + 3);
}

KEEP int cs_right(int value)
{
    return cs_leaf(value + 4);
}

KEEP int cs_diamond(int value)
{
    if (cs_choice) {
        return cs_left(value + 1);
    }
    return cs_right(value + 2);
}

KEEP int cs_recursive(int value, int depth)
{
    if (!depth) {
        return cs_leaf(value);
    }
    int child = cs_recursive(value + 1, depth - 1);
    cs_sink += child;
    return child + 1;
}

KEEP int cs_tail_recursive(int value, int depth)
{
    if (depth) {
        return cs_tail_recursive(value + 1, depth - 1);
    }
    return cs_leaf(value);
}

int (*volatile cs_target)(int) = cs_leaf;

KEEP int cs_indirect(int value)
{
    return cs_target(value);
}

/* A forwarding-function control; only explicit Ghidra thunk evidence may label
 * it a thunk. Its machine code alone is also an ordinary direct tail transfer. */
KEEP int cs_forward(int value)
{
    return cs_leaf(value);
}

KEEP int cs_driver(int scenario)
{
    int result;
    switch (scenario) {
    case 0:
        result = cs_normal(10);
        break;
    case 1:
        result = cs_tail_first(20);
        break;
    case 2:
        cs_choice = 1;
        result = cs_diamond(30);
        break;
    case 3:
        cs_choice = 0;
        result = cs_diamond(30);
        break;
    case 4:
        result = cs_recursive(40, 3);
        break;
    case 5:
        result = cs_tail_recursive(50, 3);
        break;
    case 6:
        result = cs_indirect(60);
        break;
    case 7:
        result = cs_forward(70);
        break;
    default:
        return -1;
    }
    cs_sink = result;
    return result;
}

int main(int argc, char **argv)
{
    const int expected[] = {13, 24, 35, 37, 47, 54, 61, 71};
    if (argc != 2 || argv[1][0] < '0' || argv[1][0] > '7' || argv[1][1]) {
        return 2;
    }
    int scenario = argv[1][0] - '0';
    return cs_driver(scenario) == expected[scenario] ? 0 : 1;
}
