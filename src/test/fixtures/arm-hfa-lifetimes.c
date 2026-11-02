/* Immutable HFA parameters; result registers overwrite incoming physical storage. */
typedef struct FloatPair { float first; float second; } FloatPair;
typedef struct DoublePair { double first; double second; } DoublePair;
volatile float float_result;
volatile double double_result;

__attribute__((noinline, pcs("aapcs-vfp")))
float sum_floats(FloatPair value)
{
    return value.first + value.second;
}

__attribute__((noinline, pcs("aapcs-vfp")))
double sum_doubles(DoublePair value)
{
    return value.first + value.second;
}

int main(void)
{
    float_result = sum_floats((FloatPair) {6.25f, 7.5f});
    double_result = sum_doubles((DoublePair) {1.25, 2.5});
    return !(float_result == 13.75f && double_result == 3.75);
}
