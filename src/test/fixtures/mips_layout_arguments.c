/* Owned N32/N64 layout audit: distinguish nested aggregate classes and alignment. */
typedef long long word;
struct ArrayDoubles { double elements[2]; };
union DoubleChoice { double value; };
struct UnionDouble { union DoubleChoice first; double second; };
struct DoubleBox { double value; };
struct NestedDouble { struct DoubleBox first; double second; };
struct FloatBox { float value; };
struct SmallBytes { unsigned char elements[3]; };
struct Padded { float first; double second; };
struct __attribute__((aligned(16))) AlignedPair { word first, second; };
struct __attribute__((aligned(32))) AlignedMixed { double first; word second; };
volatile double layout_real;
volatile word layout_integer;
#define HOME(value) __asm__ volatile ("" : : "m" (value))
#define MARK(name) __asm__ volatile (".globl " #name "\n" #name ":\n\tnop\n" ::: "memory")
__attribute__((noinline)) void layout_array(struct ArrayDoubles value, word tail) {
    HOME(value); MARK(layout_array_body);
    layout_real = value.elements[0] + value.elements[1]; layout_integer = tail;
}
__attribute__((noinline)) void layout_union(struct UnionDouble value, word tail) {
    HOME(value); MARK(layout_union_body);
    layout_real = value.first.value + value.second; layout_integer = tail;
}
__attribute__((noinline)) void layout_nested(struct NestedDouble value, word tail) {
    HOME(value); MARK(layout_nested_body);
    layout_real = value.first.value + value.second; layout_integer = tail;
}
__attribute__((noinline)) void layout_float_box(struct FloatBox value, word tail) {
    HOME(value); MARK(layout_float_box_body);
    layout_real = value.value; layout_integer = tail;
}
__attribute__((noinline)) void layout_small(struct SmallBytes value, word tail) {
    HOME(value); MARK(layout_small_body);
    layout_integer = value.elements[0] + value.elements[1] + value.elements[2] + tail;
}
__attribute__((noinline)) void layout_padded(struct Padded value, word tail) {
    HOME(value); MARK(layout_padded_body);
    layout_real = value.first + value.second; layout_integer = tail;
}
__attribute__((noinline)) void layout_aligned(word lead, __int128 value, word tail) {
    HOME(value); MARK(layout_aligned_body);
    layout_integer = lead + (word)(value >> 64) + (word)value + tail;
}
__attribute__((noinline)) void layout_aligned_stack(word a, word b, word c, word d,
        word e, word f, word g, word h, word lead, __int128 value, word tail) {
    HOME(value); MARK(layout_aligned_stack_body);
    layout_integer = a+b+c+d+e+f+g+h+lead+(word)(value >> 64)+(word)value+tail;
}
__attribute__((noinline)) void layout_pair16(word lead, struct AlignedPair value, word tail) {
    HOME(value); MARK(layout_pair16_body);
    layout_integer = lead + value.first + value.second + tail;
}
__attribute__((noinline)) void layout_mixed32(word lead, struct AlignedMixed value, word tail) {
    HOME(value); MARK(layout_mixed32_body);
    layout_integer = lead + (word)value.first + value.second + tail;
}
__attribute__((noinline)) void layout_pair16_stack(word a, word b, word c, word d,
        word e, word f, word g, word h, word lead, struct AlignedPair value, word tail) {
    HOME(value); MARK(layout_pair16_stack_body);
    layout_integer = a+b+c+d+e+f+g+h+lead+value.first+value.second+tail;
}
__attribute__((noinline)) void layout_mixed32_edge(word a, word b, word c, word d,
        word e, word f, word g, struct AlignedMixed value, word tail) {
    HOME(value); MARK(layout_mixed32_edge_body);
    layout_integer = a+b+c+d+e+f+g+(word)value.first+value.second+tail;
}
int main(void) {
    layout_array((struct ArrayDoubles){{1.25,-2.5}},11);
    if (layout_real != -1.25 || layout_integer != 11) return 1;
    layout_union((struct UnionDouble){{3.75},-4.5},13);
    if (layout_real != -0.75 || layout_integer != 13) return 2;
    layout_nested((struct NestedDouble){{5.25},-6.5},17);
    if (layout_real != -1.25 || layout_integer != 17) return 3;
    layout_float_box((struct FloatBox){7.75f},19);
    if (layout_real != 7.75 || layout_integer != 19) return 4;
    layout_small((struct SmallBytes){{21,23,29}},31);
    if (layout_integer != 104) return 5;
    layout_padded((struct Padded){8.25f,-9.5},37);
    if (layout_real != -1.25 || layout_integer != 37) return 6;
    layout_aligned(41, ((__int128)43 << 64) | 47, 53);
    if (layout_integer != 184) return 7;
    layout_aligned_stack(1,2,3,4,5,6,7,8,59, ((__int128)61 << 64) | 67, 71);
    if (layout_integer != 294) return 8;
    layout_pair16(11, (struct AlignedPair){13,17},19);
    if (layout_integer != 60) return 9;
    layout_mixed32(23, (struct AlignedMixed){29.0,31},37);
    if (layout_integer != 120) return 10;
    layout_pair16_stack(1,2,3,4,5,6,7,8,41,(struct AlignedPair){43,47},53);
    if (layout_integer != 220) return 11;
    layout_mixed32_edge(1,2,3,4,5,6,7,(struct AlignedMixed){59.0,61},67);
    return layout_integer != 215;
}
