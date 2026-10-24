int private_count = 19;
int scoped_value = 61;

__attribute__((noinline)) int first_scope(void)
{
    static int private_count = 37;
    return private_count;
}

__attribute__((noinline)) int second_scope(void)
{
    static int private_count = 83;
    return private_count;
}

#ifdef FORGE_QUALIFIED_NAMES
/* A real global definition must retain bare-name lookup beside scoped names. */
__attribute__((noinline)) int curated_same(void)
{
    return 29;
}
#endif

int main(void)
{
    int first = first_scope();
    int second = second_scope();
#ifdef FORGE_QUALIFIED_NAMES
    if (curated_same() != 29) {
        return 1;
    }
#endif
    return first != 37 || second != 83 || private_count != 19 || scoped_value != 61;
}
