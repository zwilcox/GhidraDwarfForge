/* The assembly oracle keeps both incoming argument registers unchanged. */
volatile int below_sink = -1;
volatile int middle_sink = -1;

extern int below_entry(int left, int right);
extern int middle_entry(int left, int right);

int main(void)
{
    int below = below_entry(19, 23);
    int middle = middle_entry(17, 25);
    return below != 42 || middle != 42 || below_sink != 42 || middle_sink != 42;
}
