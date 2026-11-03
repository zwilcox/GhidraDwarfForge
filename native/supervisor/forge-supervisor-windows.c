/* Windows validator process owner. See docs/VALIDATOR-SUPERVISION.md. */
#define _WIN32_WINNT 0x0602
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

_Static_assert(sizeof(DWORD) == 4 && sizeof(WCHAR) == 2 && sizeof(ULONGLONG) == 8, "Windows ABI widths");
#define CLEANUP_MS 5000
#define MAX_TIMEOUT_MS 3600000
#define MAX_OUTPUT_BYTES (256ULL * 1024 * 1024)

static volatile LONG interrupted;
static BOOL WINAPI interrupt_handler(DWORD event) {
    if (event != CTRL_C_EVENT && event != CTRL_BREAK_EVENT && event != CTRL_CLOSE_EVENT) return FALSE;
    InterlockedExchange(&interrupted, 1);
    return TRUE;
}

static bool number(const wchar_t *text, uint64_t maximum, uint64_t *value) {
    if (!*text) return false;
    *value = 0;
    for (const wchar_t *p = text; *p; p++) {
        if (*p < L'0' || *p > L'9' || *value > (maximum - (*p - L'0')) / 10) return false;
        *value = *value * 10 + (*p - L'0');
    }
    return *value > 0 && *value <= maximum;
}

static HANDLE exclusive(const wchar_t *path) {
    return CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
}

static bool write_all(HANDLE output, const void *buffer, DWORD length) {
    const char *cursor = buffer;
    while (length) {
        DWORD written = 0;
        if (!WriteFile(output, cursor, length, &written, NULL) || written == 0) return false;
        cursor += written;
        length -= written;
    }
    return true;
}

/* Quote each argv element using the native CRT rules, without cmd.exe or a
 * locale-dependent narrow conversion. The explicit application path selects
 * the executable independently of command-line parsing. */
static wchar_t *command_line(int argc, wchar_t **argv) {
    size_t size = 1;
    for (int i = 0; i < argc; i++) {
        size += 2 * wcslen(argv[i]) + 3;
        if (size > 32767) return NULL;
    }
    wchar_t *result = calloc(size, sizeof(wchar_t));
    if (!result) return NULL;
    wchar_t *out = result;
    for (int i = 0; i < argc; i++) {
        if (i) *out++ = L' ';
        *out++ = L'"';
        const wchar_t *in = argv[i];
        while (*in) {
            size_t slashes = 0;
            while (*in == L'\\') { slashes++; in++; }
            size_t copies = (*in == L'"' || !*in) ? slashes * 2 : slashes;
            while (copies--) *out++ = L'\\';
            if (*in == L'"') *out++ = L'\\';
            if (*in) *out++ = *in++;
        }
        *out++ = L'"';
    }
    return result;
}

typedef struct {
    HANDLE pipe;
    HANDLE log;
    uint64_t observed;
    uint64_t retained;
    bool eof;
} stream;

static bool drain(stream *output, uint64_t cap, bool *exceeded) {
    if (output->eof) return true;
    DWORD available = 0;
    if (!PeekNamedPipe(output->pipe, NULL, 0, NULL, &available, NULL)) {
        if (GetLastError() != ERROR_BROKEN_PIPE) return false;
        output->eof = true;
        CloseHandle(output->pipe);
        output->pipe = INVALID_HANDLE_VALUE;
        return true;
    }
    if (!available) return true;
    char bytes[16384];
    DWORD count = 0;
    if (!ReadFile(output->pipe, bytes, available < sizeof(bytes) ? available : sizeof(bytes), &count, NULL)) return false;
    output->observed += count;
    DWORD keep = (DWORD)(count < cap - output->retained ? count : cap - output->retained);
    if (!write_all(output->log, bytes, keep)) return false;
    output->retained += keep;
    if (output->observed > cap) *exceeded = true;
    return true;
}

int wmain(int argc, wchar_t **argv) {
    if (argc == 2 && wcscmp(argv[1], L"--version") == 0) {
        puts("forge-validator-supervisor 1 windows-job");
        return 0;
    }
    uint64_t timeout, cap;
    if (argc < 8 || !number(argv[1], MAX_TIMEOUT_MS, &timeout) || !number(argv[2], MAX_OUTPUT_BYTES, &cap) ||
            wcscmp(argv[6], L"--") != 0 || !(wcslen(argv[7]) >= 3 &&
            ((argv[7][1] == L':' && (argv[7][2] == L'\\' || argv[7][2] == L'/')) ||
             (argv[7][0] == L'\\' && argv[7][1] == L'\\')))) {
        fputs("usage: supervisor timeout-ms stream-byte-cap status-new stdout-new stderr-new -- absolute-tool [args...]\n", stderr);
        return 64;
    }
    wchar_t *command = command_line(argc - 7, argv + 7);
    if (!command) { fputs("supervisor command exceeds native bound\n", stderr); return 64; }
    HANDLE control = GetStdHandle(STD_INPUT_HANDLE);
    if (!control || control == INVALID_HANDLE_VALUE || GetFileType(control) != FILE_TYPE_PIPE ||
            !SetConsoleCtrlHandler(interrupt_handler, TRUE)) {
        fputs("supervisor requires a cancellation pipe\n", stderr); free(command); return 70;
    }
    HANDLE status_file = exclusive(argv[3]);
    HANDLE logs[2] = { INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE };
    HANDLE reads[2] = { INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE };
    HANDLE writes[2] = { INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE };
    HANDLE job = NULL, input = INVALID_HANDLE_VALUE;
    LPPROC_THREAD_ATTRIBUTE_LIST attributes = NULL;
    bool attributes_initialized = false;
    PROCESS_INFORMATION process = {0};
    int result = 70;
    if (status_file == INVALID_HANDLE_VALUE) goto finished;
    logs[0] = exclusive(argv[4]);
    logs[1] = exclusive(argv[5]);
    if (logs[0] == INVALID_HANDLE_VALUE || logs[1] == INVALID_HANDLE_VALUE) goto finished;
    SECURITY_ATTRIBUTES inherited = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    for (size_t i = 0; i < 2; i++) {
        if (!CreatePipe(&reads[i], &writes[i], &inherited, 0) ||
                !SetHandleInformation(reads[i], HANDLE_FLAG_INHERIT, 0)) goto finished;
    }
    input = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &inherited,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    job = CreateJobObjectW(NULL, NULL);
    if (input == INVALID_HANDLE_VALUE || !job) goto finished;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) goto finished;
    SIZE_T attribute_size = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attribute_size);
    if (!attribute_size || GetLastError() != ERROR_INSUFFICIENT_BUFFER) goto finished;
    attributes = HeapAlloc(GetProcessHeap(), 0, attribute_size);
    if (!attributes || !InitializeProcThreadAttributeList(attributes, 1, 0, &attribute_size)) goto finished;
    attributes_initialized = true;
    HANDLE inherit_list[3] = { input, writes[0], writes[1] };
    if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            inherit_list, sizeof(inherit_list), NULL, NULL)) goto finished;
    STARTUPINFOEXW startup = {0};
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = input;
    startup.StartupInfo.hStdOutput = writes[0];
    startup.StartupInfo.hStdError = writes[1];
    startup.lpAttributeList = attributes;
    ULONGLONG started = GetTickCount64();
    if (!CreateProcessW(argv[7], command, NULL, NULL, TRUE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
            NULL, NULL, &startup.StartupInfo, &process)) goto finished;
    /* The process cannot spawn a descendant before association succeeds. */
    if (!AssignProcessToJobObject(job, process.hProcess) || ResumeThread(process.hThread) == (DWORD)-1) goto finished;
    CloseHandle(process.hThread);
    process.hThread = NULL;
    for (size_t i = 0; i < 2; i++) { CloseHandle(writes[i]); writes[i] = INVALID_HANDLE_VALUE; }
    stream outputs[2] = {{ reads[0], logs[0], 0, 0, false }, { reads[1], logs[1], 0, 0, false }};
    const char *reason = NULL;
    bool root_done = false, all_gone = false, cleanup_ok = true, exceeded = false;
    DWORD exit_code = STILL_ACTIVE;
    ULONGLONG cleanup_started = 0;
    for (;;) {
        if (reason && !all_gone && !TerminateJobObject(job, 125)) cleanup_ok = false;
        if (!root_done) {
            DWORD waited = WaitForSingleObject(process.hProcess, 0);
            if (waited == WAIT_OBJECT_0) {
                root_done = true;
                if (!GetExitCodeProcess(process.hProcess, &exit_code)) { reason = "internal_error"; cleanup_ok = false; }
                /* ActiveProcesses includes terminated processes until their
                 * references are released. Our own root handle must not make
                 * a successful exit look like a surviving descendant. Retain
                 * the exit observation/code, then release the handle before
                 * querying job accounting. Never wait on a closed handle. */
                if (!CloseHandle(process.hProcess)) { reason = "internal_error"; cleanup_ok = false; }
                process.hProcess = NULL;
            }
            else if (waited != WAIT_TIMEOUT) { reason = "internal_error"; cleanup_ok = false; }
        }
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting;
        if (!QueryInformationJobObject(job, JobObjectBasicAccountingInformation, &accounting, sizeof(accounting), NULL)) {
            reason = "internal_error"; cleanup_ok = false;
        }
        else all_gone = accounting.ActiveProcesses == 0;
        for (size_t i = 0; i < 2; i++) {
            if (!drain(&outputs[i], cap, &exceeded)) { reason = "internal_error"; cleanup_ok = false; }
        }
        ULONGLONG now = GetTickCount64();
        if (!reason) {
            DWORD available = 0;
            BOOL control_ok = PeekNamedPipe(control, NULL, 0, NULL, &available, NULL);
            if (exceeded) reason = "output_limit";
            else if (interrupted || available || (!control_ok && GetLastError() == ERROR_BROKEN_PIPE)) reason = "cancelled";
            else if (!control_ok) { reason = "internal_error"; cleanup_ok = false; }
            else if (root_done && !all_gone) reason = "descendants";
            else if (now - started >= timeout) reason = "timeout";
        }
        if (all_gone && root_done && outputs[0].eof && outputs[1].eof) break;
        if (reason && !cleanup_started) cleanup_started = now;
        if (reason && now - cleanup_started >= CLEANUP_MS) { cleanup_ok = false; break; }
        Sleep(10);
    }
    bool complete = cleanup_ok && all_gone && root_done && outputs[0].eof && outputs[1].eof;
    if (!reason) reason = exit_code == 0 && complete ? "completed" : "tool_error";
    for (size_t i = 0; i < 2; i++) {
        reads[i] = outputs[i].pipe;
        if (!FlushFileBuffers(logs[i])) complete = false;
        if (!CloseHandle(logs[i])) complete = false;
        logs[i] = INVALID_HANDLE_VALUE;
    }
    char record[1024];
    int length = snprintf(record, sizeof(record),
        "{\"schemaVersion\":1,\"reason\":\"%s\",\"exitCode\":%lu,\"exitSignal\":0,"
        "\"cleanupComplete\":%s,\"stdoutObserved\":%llu,\"stdoutRetained\":%llu,"
        "\"stderrObserved\":%llu,\"stderrRetained\":%llu}\n", reason, (unsigned long)exit_code,
        complete ? "true" : "false", (unsigned long long)outputs[0].observed,
        (unsigned long long)outputs[0].retained, (unsigned long long)outputs[1].observed,
        (unsigned long long)outputs[1].retained);
    bool recorded = length > 0 && (size_t)length < sizeof(record) && write_all(status_file, record, (DWORD)length);
    if (!FlushFileBuffers(status_file)) recorded = false;
    result = recorded && complete && exit_code == 0 && strcmp(reason, "completed") == 0 ? 0 : 20;
finished:
    if (result == 70) {
        fprintf(stderr, "supervisor setup failed (Windows error %lu)\n", (unsigned long)GetLastError());
        if (process.hProcess) {
            TerminateProcess(process.hProcess, 125);
            WaitForSingleObject(process.hProcess, CLEANUP_MS);
        }
    }
    if (job) CloseHandle(job);
    if (process.hThread) CloseHandle(process.hThread);
    if (process.hProcess) CloseHandle(process.hProcess);
    if (attributes_initialized) DeleteProcThreadAttributeList(attributes);
    if (attributes) HeapFree(GetProcessHeap(), 0, attributes);
    if (input != INVALID_HANDLE_VALUE) CloseHandle(input);
    for (size_t i = 0; i < 2; i++) {
        if (logs[i] != INVALID_HANDLE_VALUE) CloseHandle(logs[i]);
        if (reads[i] != INVALID_HANDLE_VALUE) CloseHandle(reads[i]);
        if (writes[i] != INVALID_HANDLE_VALUE) CloseHandle(writes[i]);
    }
    if (status_file != INVALID_HANDLE_VALUE) CloseHandle(status_file);
    free(command);
    return result;
}
