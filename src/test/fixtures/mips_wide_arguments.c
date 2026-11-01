/* Owned N32/N64 aggregate, positional floating and exhausted-slot regression. */
typedef long long word;
struct Pair { word first; word second; };
struct Large { word first; word second; word third; };
volatile word integer_sink;
volatile double real_sink;
volatile struct Pair pair_sink;
volatile struct Large large_sink;
__attribute__((noinline)) word wide_words(word a, word b, word c, word d, word e,
        word f, word g, word h, word i, word j) {
    integer_sink = a+b+c+d+e+f+g+h+i+j;
    return integer_sink;
}
__attribute__((noinline)) struct Pair wide_pair(struct Pair value) {
    pair_sink = value;
    return value;
}
__attribute__((noinline)) struct Large wide_large(struct Large value) {
    large_sink = value;
    return value;
}
__attribute__((noinline)) word wide_mixed(word a, double b, int c, float d,
        struct Pair e, word f, double g, word h, int tail) {
    integer_sink = a+c+e.first+e.second+f+h+tail;
    real_sink = b+d+g;
    return integer_sink;
}
int main(void) {
    word sum=wide_words(11,22,33,44,55,66,77,88,909,-1010);
    struct Pair pair=wide_pair((struct Pair){101,-202});
    struct Large large=wide_large((struct Large){303,-404,505});
    word mixed=wide_mixed(17,1.25,-19,-2.5f,(struct Pair){101,-202},23,3.75,29,-31);
    return sum != 295 || pair.first != 101 || pair.second != -202 ||
        large.first != 303 || large.second != -404 || large.third != 505 ||
        mixed != -82 || real_sink != 2.5;
}
