/* Exercise actual Windows pipe EOF after a successful availability snapshot. */
#define _WIN32_WINNT 0x0602
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdbool.h>
#include <stdio.h>
#include <wchar.h>

static HANDLE pending_writer;
static bool intercepted;
static bool invalidate_reader;

static BOOL controlled_peek(HANDLE pipe, LPVOID buffer, DWORD capacity,
        LPDWORD read, LPDWORD available, LPDWORD remaining) {
    BOOL result = PeekNamedPipe(pipe, buffer, capacity, read, available, remaining);
    if (result && available && *available && invalidate_reader) {
        if (!CloseHandle(pipe)) return FALSE;
        intercepted = true;
        return result;
    }
    if (result && available && *available && pending_writer && !intercepted) {
        if (!TerminateProcess(pending_writer, 125) ||
                WaitForSingleObject(pending_writer, 5000) != WAIT_OBJECT_0) {
            SetLastError(ERROR_GEN_FAILURE);
            return FALSE;
        }
        intercepted = true;
    }
    return result;
}

#define PeekNamedPipe controlled_peek
#define wmain supervisor_program_main
#include "../../../native/supervisor/forge-supervisor-windows.c"
#undef wmain
#undef PeekNamedPipe

static int drain_control(const wchar_t *mode, const wchar_t *path) {
    HANDLE reader = INVALID_HANDLE_VALUE, writer = INVALID_HANDLE_VALUE;
    HANDLE log = INVALID_HANDLE_VALUE;
    int result = 1;
    if (!CreatePipe(&reader, &writer, NULL, 4096)) goto finished;
    log = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (log == INVALID_HANDLE_VALUE) goto finished;
    char bytes[128];
    memset(bytes, 'q', sizeof(bytes));
    DWORD written = 0;
    if (!WriteFile(writer, bytes, sizeof(bytes), &written, NULL) || written != sizeof(bytes)) goto finished;
    CloseHandle(writer);
    writer = INVALID_HANDLE_VALUE;
    bool bad_read = wcscmp(mode, L"bad-read") == 0;
    bool bad_log = wcscmp(mode, L"bad-log") == 0;
    uint64_t cap = wcscmp(mode, L"capped") == 0 ? 64 : 256;
    invalidate_reader = bad_read;
    stream output = { reader, bad_log ? INVALID_HANDLE_VALUE : log, 0, 0, false };
    bool exceeded = false;
    bool drained = drain(&output, cap, &exceeded);
    DWORD error = GetLastError();
    reader = bad_read && intercepted ? INVALID_HANDLE_VALUE : output.pipe;
    if (bad_read || bad_log) {
        result = !drained && !output.eof && !exceeded && error == ERROR_INVALID_HANDLE &&
            output.observed == (bad_read ? 0 : sizeof(bytes)) && output.retained == 0 &&
            (!bad_read || intercepted) ? 0 : 1;
    }
    else {
        bool eof = drain(&output, cap, &exceeded);
        reader = output.pipe;
        bool repeat = drain(&output, cap, &exceeded);
        DWORD expected = cap < sizeof(bytes) ? (DWORD)cap : sizeof(bytes);
        char retained[128];
        DWORD count = 0;
        LARGE_INTEGER size;
        bool contents = GetFileSizeEx(log, &size) && size.QuadPart == expected &&
            SetFilePointer(log, 0, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER &&
            ReadFile(log, retained, sizeof(retained), &count, NULL) && count == expected &&
            memcmp(retained, bytes, count) == 0;
        result = drained && eof && repeat && output.eof && output.pipe == INVALID_HANDLE_VALUE &&
            output.observed == sizeof(bytes) && output.retained == expected &&
            exceeded == (cap < sizeof(bytes)) && contents ? 0 : 1;
    }
    printf("mode=%ls drained=%d eof=%d observed=%llu retained=%llu exceeded=%d error=%lu result=%d\n",
        mode, drained, output.eof, (unsigned long long)output.observed,
        (unsigned long long)output.retained, exceeded, (unsigned long)error, result);
finished:
    if (reader != INVALID_HANDLE_VALUE) CloseHandle(reader);
    if (writer != INVALID_HANDLE_VALUE) CloseHandle(writer);
    if (log != INVALID_HANDLE_VALUE) CloseHandle(log);
    return result;
}

int wmain(int argc, wchar_t **argv) {
    if (argc == 2 && wcscmp(argv[1], L"--writer") == 0) {
        char bytes[65536];
        memset(bytes, 'x', sizeof(bytes));
        DWORD count;
        return WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), bytes, sizeof(bytes), &count, NULL) ? 0 : 2;
    }
    if (argc != 3) return 64;
    if (wcscmp(argv[1], L"race") != 0) {
        if (wcscmp(argv[1], L"data") && wcscmp(argv[1], L"capped") &&
                wcscmp(argv[1], L"bad-read") && wcscmp(argv[1], L"bad-log")) return 64;
        return drain_control(argv[1], argv[2]);
    }
    SECURITY_ATTRIBUTES inherited = { sizeof(inherited), NULL, TRUE };
    HANDLE read_pipe = INVALID_HANDLE_VALUE, write_pipe = INVALID_HANDLE_VALUE;
    HANDLE input = INVALID_HANDLE_VALUE, log = INVALID_HANDLE_VALUE;
    PROCESS_INFORMATION child = {0};
    int result = 1;
    if (!CreatePipe(&read_pipe, &write_pipe, &inherited, 4096) ||
            !SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0)) goto finished;
    input = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        &inherited, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    log = CreateFileW(argv[2], GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (input == INVALID_HANDLE_VALUE || log == INVALID_HANDLE_VALUE) goto finished;
    wchar_t executable[4096], command[8192];
    DWORD length = GetModuleFileNameW(NULL, executable, 4096);
    if (!length || length >= 4096 || swprintf(command, 8192, L"\"%ls\" --writer", executable) < 0) goto finished;
    STARTUPINFOW startup = {0};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = input;
    startup.hStdOutput = write_pipe;
    startup.hStdError = write_pipe;
    if (!CreateProcessW(executable, command, NULL, NULL, TRUE, CREATE_NO_WINDOW,
            NULL, NULL, &startup, &child)) goto finished;
    CloseHandle(write_pipe);
    write_pipe = INVALID_HANDLE_VALUE;
    ULONGLONG deadline = GetTickCount64() + 5000;
    DWORD available = 0;
    while (!available && GetTickCount64() < deadline) {
        if (!PeekNamedPipe(read_pipe, NULL, 0, NULL, &available, NULL)) goto finished;
        Sleep(1);
    }
    if (!available) goto finished;
    pending_writer = child.hProcess;
    stream output = { read_pipe, log, 0, 0, false };
    bool exceeded = false;
    bool drained = drain(&output, 4096, &exceeded);
    DWORD error = GetLastError();
    read_pipe = output.pipe;
    printf("intercepted=%d snapshot=%lu drained=%d eof=%d observed=%llu error=%lu\n",
        intercepted, (unsigned long)available, drained, output.eof,
        (unsigned long long)output.observed, (unsigned long)error);
    LARGE_INTEGER size;
    result = intercepted && drained && output.eof && output.pipe == INVALID_HANDLE_VALUE &&
        output.observed == 0 && output.retained == 0 && !exceeded &&
        GetFileSizeEx(log, &size) && size.QuadPart == 0 && drain(&output, 4096, &exceeded) ? 0 : 1;
finished:
    if (child.hProcess) {
        if (WaitForSingleObject(child.hProcess, 0) == WAIT_TIMEOUT) {
            TerminateProcess(child.hProcess, 125);
            WaitForSingleObject(child.hProcess, 5000);
        }
        CloseHandle(child.hProcess);
    }
    if (child.hThread) CloseHandle(child.hThread);
    if (read_pipe != INVALID_HANDLE_VALUE) CloseHandle(read_pipe);
    if (write_pipe != INVALID_HANDLE_VALUE) CloseHandle(write_pipe);
    if (input != INVALID_HANDLE_VALUE) CloseHandle(input);
    if (log != INVALID_HANDLE_VALUE) CloseHandle(log);
    return result;
}
