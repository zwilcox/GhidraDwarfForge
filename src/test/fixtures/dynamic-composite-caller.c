/* The unchanged aggregate main is compiled as aggregate_main at -O0. */
extern int aggregate_main(void);
extern void capture_scalar(unsigned long long value);
extern volatile unsigned long long observed_scalar;

int main(void) {
    if (aggregate_main() != 0) {
        return 1;
    }
    capture_scalar(0x1122334455667788ULL);
    return observed_scalar != 0x1122334455667788ULL;
}
