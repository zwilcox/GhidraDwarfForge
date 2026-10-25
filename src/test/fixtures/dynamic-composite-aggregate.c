typedef struct Pair {
    int first;
    int second;
} Pair;

volatile int observed_first;
volatile int observed_second;

__attribute__((noinline)) void capture_pair(Pair value) {
    observed_first = value.first;
    observed_second = value.second;
}

int main(void) {
    Pair value = { -19, 37 };
    capture_pair(value);
    return observed_first == -19 && observed_second == 37 ? 0 : 1;
}
