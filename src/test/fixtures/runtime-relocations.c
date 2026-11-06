/* Real dynamic tables, including clustered relative pointers for RELR. */
#include <stdio.h>

int relocation_values[8] = {1, 2, 3, 4, 5, 6, 7, 8};
#define POINTERS &relocation_values[0], &relocation_values[1], &relocation_values[2], &relocation_values[3], \
    &relocation_values[4], &relocation_values[5], &relocation_values[6], &relocation_values[7]
int *relocation_pointers[] = {POINTERS, POINTERS, POINTERS, POINTERS, POINTERS, POINTERS, POINTERS, POINTERS,
    POINTERS, POINTERS};

int relocation_probe(void) {
    return *relocation_pointers[0] + *relocation_pointers[79];
}

int main(void) {
    printf("runtime-relocations=%d\n", relocation_probe());
    return relocation_probe() == 9 ? 0 : 1;
}
