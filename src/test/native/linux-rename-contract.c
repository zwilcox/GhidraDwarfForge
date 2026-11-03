#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>

/* Compile against each Linux host's actual headers before the isolated JNA test. */
_Static_assert(sizeof(int) == 4, "renameat2 int ABI must be 32 bits");
_Static_assert(sizeof(unsigned int) == 4, "renameat2 flags must be 32 bits");
_Static_assert(AT_FDCWD == -100, "AT_FDCWD differs from audited binding");
_Static_assert(RENAME_NOREPLACE == 1, "RENAME_NOREPLACE differs from audited binding");

int main(void) {
    int (*checked_signature)(int, const char *, int, const char *, unsigned int) = renameat2;
    if (checked_signature == NULL) {
        return 1;
    }
    puts("linux-rename-contract=PASS int=32 flags=32 AT_FDCWD=-100 RENAME_NOREPLACE=1");
    return 0;
}
