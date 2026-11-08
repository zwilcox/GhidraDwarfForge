#include <stdint.h>

uint64_t counter = 23;
extern uint64_t observed(uint64_t x);
extern uint64_t failed(void);
extern void empty(void);

int main(void) {
    empty();
    return observed(41) == 41 && failed() == 7 ? 0 : 1;
}
