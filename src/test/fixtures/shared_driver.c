extern int recovered_add(int left, int right, int unused, int register_seed);

int main(void) {
    return recovered_add(19, 23, 0, 31) == 42 ? 0 : 1;
}
