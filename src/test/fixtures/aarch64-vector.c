/* AArch64 NEON storage oracle. Analyst array views preserve lane layout,
 * not the compiler-only GNU vector calling type. */
#include <stdint.h>
typedef int32_t IntLanes __attribute__((vector_size(16)));
typedef float FloatLanes __attribute__((vector_size(16)));
_Static_assert(sizeof(IntLanes) == 16 && sizeof(FloatLanes) == 16, "lane widths");
volatile IntLanes vector_seen;
volatile FloatLanes float_seen;
#define PROBE __attribute__((noinline, noclone))

PROBE IntLanes vector_plain(IntLanes value) {
    vector_seen = value;
    return value + (IntLanes){1, 2, 3, 4};
}

PROBE IntLanes vector_copy(IntLanes value) {
    vector_seen = value;
    __asm__ volatile("movi v0.16b, #0" ::: "v0");
    return value + (IntLanes){1, 2, 3, 4};
}

static __attribute__((always_inline)) inline void clear_vector_carriers(void) {
    /* The real clobbers force compiler-owned 128-bit spill/reload storage.
     * The compiler preserves the caller's callee-saved register portions. */
    /* Declare the clobber boundary before the multi-instruction block so GCC
     * moves its debug location to the spill before the first real clobber.
     * This emits no instructions; the following block still zeros every lane. */
    __asm__ volatile(""
        : : : "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
            "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31", "memory");
    __asm__ volatile(
        "movi v0.16b, #0\nmovi v1.16b, #0\nmovi v2.16b, #0\nmovi v3.16b, #0\n"
        "movi v4.16b, #0\nmovi v5.16b, #0\nmovi v6.16b, #0\nmovi v7.16b, #0\n"
        "movi v8.16b, #0\nmovi v9.16b, #0\nmovi v10.16b, #0\nmovi v11.16b, #0\n"
        "movi v12.16b, #0\nmovi v13.16b, #0\nmovi v14.16b, #0\nmovi v15.16b, #0\n"
        "movi v16.16b, #0\nmovi v17.16b, #0\nmovi v18.16b, #0\nmovi v19.16b, #0\n"
        "movi v20.16b, #0\nmovi v21.16b, #0\nmovi v22.16b, #0\nmovi v23.16b, #0\n"
        "movi v24.16b, #0\nmovi v25.16b, #0\nmovi v26.16b, #0\nmovi v27.16b, #0\n"
        "movi v28.16b, #0\nmovi v29.16b, #0\nmovi v30.16b, #0\nmovi v31.16b, #0\n"
        : : : "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
            "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31", "memory");
}

PROBE IntLanes vector_stack(IntLanes value) {
    clear_vector_carriers();
    return value + (IntLanes){1, 2, 3, 4};
}

PROBE IntLanes vector_alias(IntLanes value) {
    /* This global store is not proven disjoint from the compiler's spill by
     * the shared abstract interpreter. Its conservative gap must survive reload. */
    vector_seen = value;
    clear_vector_carriers();
    return value + (IntLanes){1, 2, 3, 4};
}

PROBE FloatLanes vector_float(FloatLanes value) {
    float_seen = value;
    return value + (FloatLanes){0.5f, 1.25f, -0.75f, 2.0f};
}

PROBE IntLanes vector_stack_arg(IntLanes a, IntLanes b, IntLanes c, IntLanes d,
        IntLanes e, IntLanes f, IntLanes g, IntLanes h, IntLanes value) {
    __asm__ volatile("" ::: "memory");
    return a + h + value;
}

static int same(IntLanes value, IntLanes expected) {
    return value[0] == expected[0] && value[1] == expected[1] &&
        value[2] == expected[2] && value[3] == expected[3];
}

int main(void) {
    if (!same(vector_plain((IntLanes){11, -22, 33, -44}), (IntLanes){12, -20, 36, -40})) return 1;
    if (!same(vector_copy((IntLanes){101, -202, 303, -404}), (IntLanes){102, -200, 306, -400})) return 2;
    if (!same(vector_stack((IntLanes){501, -602, 703, -804}), (IntLanes){502, -600, 706, -800})) return 3;
    if (!same(vector_alias((IntLanes){1501, -1602, 1703, -1804}), (IntLanes){1502, -1600, 1706, -1800})) return 4;
    FloatLanes real = vector_float((FloatLanes){1.25f, -2.5f, 3.75f, -4.0f});
    if (real[0] != 1.75f || real[1] != -1.25f || real[2] != 3.0f || real[3] != -2.0f) return 5;
    IntLanes result = vector_stack_arg((IntLanes){1,2,3,4}, (IntLanes){2,3,4,5},
        (IntLanes){3,4,5,6}, (IntLanes){4,5,6,7}, (IntLanes){5,6,7,8},
        (IntLanes){6,7,8,9}, (IntLanes){7,8,9,10}, (IntLanes){8,9,10,11},
        (IntLanes){901,-902,903,-904});
    return !same(result, (IntLanes){910,-891,916,-889});
}
