/* C callers establish the selected ABI; assembly owns the exact clobber boundaries. */
typedef struct FloatPair {
#if FORGE_MIXED
    unsigned first;
#else
    float first;
#endif
    float second;
} FloatPair;
#if FORGE_MIXED
volatile FloatPair control_input = {0x40c80000u, 7.5f};
#else
volatile FloatPair control_input = {6.25f, 7.5f};
#endif
#if FORGE_BASE_PCS
#define CONTROL_PCS "aapcs"
#else
#define CONTROL_PCS "aapcs-vfp"
#endif
volatile unsigned control_guard;
#if FORGE_MIXED
typedef unsigned ControlResult;
#else
typedef float ControlResult;
#endif

__attribute__((pcs(CONTROL_PCS)))
extern ControlResult hfa_control(FloatPair value, volatile unsigned *destination, unsigned replacement);
__attribute__((pcs(CONTROL_PCS)))
extern ControlResult hfa_alias(FloatPair value, volatile unsigned *destination, unsigned replacement);

int main(void)
{
#if FORGE_HFA_ALIAS
    ControlResult result = hfa_alias(control_input, &control_guard, 0x12345678u);
#else
    ControlResult result = hfa_control(control_input, &control_guard, 0x12345678u);
#endif
    unsigned expected_guard = FORGE_HFA_CONTROL == 6 && !FORGE_HFA_ALIAS ? 0x12345678u : 0;
#if FORGE_MIXED
    /* The assembly returns the raw bits after its explicit floating arithmetic. */
    unsigned expected_result = FORGE_HFA_CONTROL == 0 ? 0x415c0000u : 0x40c80000u;
#else
    float expected_result = FORGE_HFA_CONTROL == 0 ? 13.75f : 6.25f;
#endif
    return result != expected_result || control_guard != expected_guard;
}
