int recovered_add(int left, int right) {
    int sum = left + right;
    return sum;
}

int main(void) {
    return recovered_add(19, 23) == 42 ? 0 : 1;
}
