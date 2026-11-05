/* Independent native children for process-tree CPU/memory/timeout controls. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <wchar.h>

static ULONGLONG cpu_ticks(void) {
    FILETIME created, exited, kernel, user;
    if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user)) ExitProcess(71);
    ULARGE_INTEGER k = { .LowPart = kernel.dwLowDateTime, .HighPart = kernel.dwHighDateTime };
    ULARGE_INTEGER u = { .LowPart = user.dwLowDateTime, .HighPart = user.dwHighDateTime };
    return k.QuadPart + u.QuadPart;
}

int wmain(int argc, wchar_t **argv) {
    if (argc == 8 && wcscmp(argv[1], L"--args") == 0) {
        const wchar_t *expected[] = {L"plain", L"sp ace", L"quo\"te", L"trailing\\", L"", L"unicode-\u03bb"};
        for (int i = 0; i < 6; i++) if (wcscmp(argv[i + 2], expected[i]) != 0) return 65;
        puts("arguments=PASS");
        return 0;
    }
    if (argc != 2) return 64;
    if (wcscmp(argv[1], L"--child") == 0 || wcscmp(argv[1], L"--sleep-child") == 0) {
        printf("child:%lu\n", (unsigned long)GetCurrentProcessId()); fflush(stdout);
        fputs("child-stderr\n", stderr); fflush(stderr);
        if (wcscmp(argv[1], L"--sleep-child") == 0) { Sleep(30000); return 0; }
        volatile unsigned char *memory = VirtualAlloc(NULL, 64 * 1024 * 1024,
            MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!memory) return 70;
        /* Commit the region but touch just one page: the job measurement must
         * reflect commitment, not substitute resident-set accounting. */
        memory[0] = 42;
        ULONGLONG started = cpu_ticks();
        volatile unsigned long sink = 0;
        while (cpu_ticks() - started < 2000000) {
            for (unsigned long i = 0; i < 100000; i++) sink += i;
        }
        printf("child-done:%lu\n", sink); fflush(stdout);
        VirtualFree((void *)memory, 0, MEM_RELEASE);
        return 0;
    }
    if (wcscmp(argv[1], L"--error") == 0) return 17;
    if (wcscmp(argv[1], L"--spawn") != 0 && wcscmp(argv[1], L"--timeout") != 0) return 64;
    wchar_t executable[32768], command[32768];
    DWORD length = GetModuleFileNameW(NULL, executable, 32768);
    if (!length || length > 32000) return 70;
    if (swprintf(command, 32768, L"\"%ls\" %ls", executable,
            wcscmp(argv[1], L"--timeout") == 0 ? L"--sleep-child" : L"--child") < 0) return 70;
    STARTUPINFOW startup = {0};
    PROCESS_INFORMATION process = {0};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    if (!CreateProcessW(executable, command, NULL, NULL, TRUE, CREATE_NO_WINDOW,
            NULL, NULL, &startup, &process)) return 70;
    CloseHandle(process.hThread); CloseHandle(process.hProcess);
    puts("root-exit");
    return 0; /* The measuring job must include the still-running child. */
}
