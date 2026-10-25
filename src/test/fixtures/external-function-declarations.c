#ifdef FORGE_DECL_LIBRARY
long imported_adjust(int value)
{
    return value + 5L;
}
#else
extern long imported_adjust(int value);
volatile long observed_result;
int main(void)
{
    observed_result = imported_adjust(7);
    return observed_result != 12;
}
#endif
