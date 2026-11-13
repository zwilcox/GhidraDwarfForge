/* SPDX-License-Identifier: MIT */
/* Compiler oracle only. Device effects are implemented by the test target. */
typedef unsigned int word32;
_Static_assert(sizeof(word32) == 4, "fixture requires a 32-bit register word");

enum StatusFlags {
    STATUS_READY = 1,
    STATUS_BUSY = 8,
    STATUS_ERROR = 128
};

struct Fields {
    unsigned a : 3;
    unsigned b : 5;
    unsigned reserved : 24;
};

struct __attribute__((packed)) ByteFields {
    unsigned a : 3;
    unsigned b : 5;
};
_Static_assert(sizeof(struct ByteFields) == 1, "base type and storage width must differ");

struct CrossFields {
    unsigned prefix : 6;
    unsigned cross : 7;
    signed sign : 3;
    unsigned reserved : 16;
};

union Register {
    word32 raw;
    struct Fields bits;
    struct ByteFields byte;
    struct CrossFields cross;
    enum StatusFlags flags;
};
_Static_assert(sizeof(union Register) == 4, "register views must overlap one word");

struct Device {
    const volatile union Register status;
    volatile word32 counter;
};
_Static_assert(sizeof(struct Device) == 8, "adjacent registers must remain adjacent");

volatile struct Device peripheral __attribute__((section(".mmio"))) = {
    .status = { .raw = 0xa5a5e28dU },
    .counter = 17
};

int main(void) {
    return 0;
}
