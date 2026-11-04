/* Owned cancellation fixture, never a successful DWARF validator. */
#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#include <process.h>
#include <wchar.h>
int wmain(int argc, wchar_t **argv) {
    if (argc != 2 || wcscmp(argv[1], L"--version") != 0) return 64;
    size_t length = wcslen(argv[0]) + 9;
    wchar_t *path = calloc(length, sizeof(wchar_t));
    if (!path) return 70;
    if (swprintf(path, length, L"%ls.started", argv[0]) < 0) return 70;
    FILE *marker = _wfopen(path, L"w");
    free(path);
    if (!marker) return 70;
    if (fprintf(marker, "%d\n", _getpid()) < 0 || fclose(marker) != 0) return 70;
    for (;;) Sleep(100);
}
#else
#include <time.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 2 || strcmp(argv[1], "--version") != 0) return 64;
    size_t length = strlen(argv[0]) + 9;
    char *path = calloc(length, 1);
    if (!path) return 70;
    if (snprintf(path, length, "%s.started", argv[0]) < 0) return 70;
    FILE *marker = fopen(path, "w");
    free(path);
    if (!marker) return 70;
    if (fprintf(marker, "%ld\n", (long)getpid()) < 0 || fclose(marker) != 0) return 70;
    const struct timespec interval = { .tv_sec = 0, .tv_nsec = 100000000 };
    for (;;) nanosleep(&interval, NULL);
}
#endif
