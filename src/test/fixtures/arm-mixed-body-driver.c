extern int mixed_body(int value);

int main(void) {
    return mixed_body(11) == 11 + 3 + 5 + 7 + 0x1234 ? 0 : 1;
}
