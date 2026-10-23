/* Runtime bit-field oracle: ordinary and packed storage share a four-byte base. */
struct word_flags {
    unsigned int a : 3;
    unsigned int b : 5;
};

struct __attribute__((packed)) byte_flags {
    unsigned int a : 3;
    unsigned int b : 5;
};

_Static_assert(sizeof(unsigned int) == 4, "fixture requires four-byte unsigned int");
_Static_assert(sizeof(struct byte_flags) == 1, "packed fixture must occupy one byte");

volatile struct word_flags word_value = { .a = 5, .b = 17 };
volatile struct byte_flags byte_value = { .a = 5, .b = 17 };

__attribute__((noinline)) int inspect_flags(void) {
    return word_value.a + word_value.b + byte_value.a + byte_value.b;
}

int main(void) {
    return inspect_flags() == 44 ? 0 : 1;
}
