/* Validation-tool startup policy only; never linked into Ghidra's libraries. */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

__attribute__((constructor)) static void require_utf8_process_code_page(void) {
    if (GetACP() != CP_UTF8) {
        fputs("validation dwarfdump requires an active UTF-8 process code page; no lossy path fallback\n", stderr);
        exit(EXIT_FAILURE);
    }
}
