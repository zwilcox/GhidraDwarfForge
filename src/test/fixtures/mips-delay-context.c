extern int delay_context(int value);

int main(void) {
    return delay_context(0) == 9 && delay_context(5) == 17 ? 0 : 1;
}
