volatile int observed;
__attribute__((noinline)) int recovered_second(int x) {
    observed = x + 3;
    return observed;
}
__attribute__((noinline)) int recovered_first(int x) {
    int next = x + 2;
    return recovered_second(next);
}
int main(void) { return recovered_first(5) == 10 ? 0 : 1; }
