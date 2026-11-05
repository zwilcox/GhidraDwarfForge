/* Test-only process-tree accounting. Not shipped in the extension. */
#define _WIN32_WINNT 0x0602
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

_Static_assert(sizeof(DWORD) == 4 && sizeof(ULONGLONG) == 8, "Windows accounting widths");
static volatile LONG interrupted;

static BOOL WINAPI cancel(DWORD event) {
    if (event != CTRL_C_EVENT && event != CTRL_BREAK_EVENT && event != CTRL_CLOSE_EVENT) return FALSE;
    InterlockedExchange(&interrupted, 1);
    return TRUE;
}

/* Native CRT quoting, with an independently selected executable; no cmd parser. */
static wchar_t *arguments(int argc, wchar_t **argv) {
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

int wmain(int argc, wchar_t **argv) {
    if (argc < 6) {
        fputs("usage: windows-measure timeout-ms metrics-new stdout-new stderr-new absolute-exe args...\n", stderr);
        return 64;
    }
    ULONGLONG timeout = 0;
    for (const wchar_t *p = argv[1]; *p; p++) {
        if (*p < L'0' || *p > L'9' || timeout > 720000) return 64;
        timeout = timeout * 10 + (*p - L'0');
    }
    if (!timeout || timeout > 7200000 || wcslen(argv[5]) < 3 ||
            !((argv[5][1] == L':' && (argv[5][2] == L'\\' || argv[5][2] == L'/')) ||
                (argv[5][0] == L'\\' && argv[5][1] == L'\\'))) return 64;
    wchar_t *command = arguments(argc - 5, argv + 5);
    if (!command) return 64;
    HANDLE metrics = CreateFileW(argv[2], GENERIC_WRITE, 0, NULL, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (metrics == INVALID_HANDLE_VALUE) { free(command); return 73; }
    SECURITY_ATTRIBUTES security = { sizeof(security), NULL, TRUE };
    HANDLE output = INVALID_HANDLE_VALUE, errors = INVALID_HANDLE_VALUE, input = INVALID_HANDLE_VALUE;
    HANDLE job = NULL;
    LPPROC_THREAD_ATTRIBUTE_LIST attributes = NULL;
    bool attributes_ready = false, assigned = false, root_done = false, clean = false;
    PROCESS_INFORMATION process = {0};
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting = {0};
    LARGE_INTEGER frequency = {0}, started = {0}, ended = {0};
    DWORD exit_code = STILL_ACTIVE, error = 0;
    const char *reason = "internal_error";
    ULONGLONG deadline = 0;
    output = CreateFileW(argv[3], GENERIC_WRITE | FILE_READ_ATTRIBUTES, FILE_SHARE_READ, &security, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (output == INVALID_HANDLE_VALUE) goto finished;
    errors = CreateFileW(argv[4], GENERIC_WRITE | FILE_READ_ATTRIBUTES, FILE_SHARE_READ, &security, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (errors == INVALID_HANDLE_VALUE) goto finished;
    input = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        &security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (input == INVALID_HANDLE_VALUE) goto finished;
    job = CreateJobObjectW(NULL, NULL);
    if (!job) goto finished;
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)) ||
            !SetConsoleCtrlHandler(cancel, TRUE) || !QueryPerformanceFrequency(&frequency)) goto finished;
    SIZE_T size = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &size);
    if (!size || GetLastError() != ERROR_INSUFFICIENT_BUFFER) goto finished;
    attributes = HeapAlloc(GetProcessHeap(), 0, size);
    if (!attributes || !InitializeProcThreadAttributeList(attributes, 1, 0, &size)) goto finished;
    attributes_ready = true;
    HANDLE inherited[3] = {input, output, errors};
    if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            inherited, sizeof(inherited), NULL, NULL)) goto finished;
    STARTUPINFOEXW startup = {0};
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = input;
    startup.StartupInfo.hStdOutput = output;
    startup.StartupInfo.hStdError = errors;
    startup.lpAttributeList = attributes;
    if (!QueryPerformanceCounter(&started)) goto finished;
    deadline = GetTickCount64() + timeout;
    if (!CreateProcessW(argv[5], command, NULL, NULL, TRUE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
            NULL, NULL, &startup.StartupInfo, &process)) goto finished;
    if (!AssignProcessToJobObject(job, process.hProcess)) goto finished;
    assigned = true;
    if (ResumeThread(process.hThread) == (DWORD)-1) goto finished;
    CloseHandle(process.hThread); process.hThread = NULL;
    for (;;) {
        if (!root_done) {
            DWORD waited = WaitForSingleObject(process.hProcess, 0);
            if (waited == WAIT_OBJECT_0) {
                if (!GetExitCodeProcess(process.hProcess, &exit_code)) goto finished;
                /* Release the root reference before testing live job membership. */
                CloseHandle(process.hProcess); process.hProcess = NULL;
                root_done = true;
            }
            else if (waited != WAIT_TIMEOUT) goto finished;
        }
        if (!QueryInformationJobObject(job, JobObjectBasicAccountingInformation,
                &accounting, sizeof(accounting), NULL)) goto finished;
        LARGE_INTEGER stdout_size, stderr_size;
        if (!GetFileSizeEx(output, &stdout_size) || !GetFileSizeEx(errors, &stderr_size)) goto finished;
        if (stdout_size.QuadPart > 256LL * 1024 * 1024 || stderr_size.QuadPart > 256LL * 1024 * 1024) {
            reason = "output_limit";
            break;
        }
        if (root_done && accounting.ActiveProcesses == 0) {
            clean = true;
            reason = exit_code == 0 ? "completed" : "tool_error";
            break;
        }
        if (interrupted || GetTickCount64() >= deadline) {
            reason = interrupted ? "cancelled" : "timeout";
            break;
        }
        Sleep(10);
    }
finished:
    if (strcmp(reason, "internal_error") == 0) error = GetLastError();
    if (!clean && process.hProcess && !assigned) {
        TerminateProcess(process.hProcess, 125);
        WaitForSingleObject(process.hProcess, 5000);
    }
    if (!clean && job && assigned) {
        if (!TerminateJobObject(job, 125) && !error) error = GetLastError();
        if (process.hProcess) {
            WaitForSingleObject(process.hProcess, 5000);
            GetExitCodeProcess(process.hProcess, &exit_code);
            CloseHandle(process.hProcess); process.hProcess = NULL;
        }
        ULONGLONG cleanup_end = GetTickCount64() + 5000;
        do {
            if (!QueryInformationJobObject(job, JobObjectBasicAccountingInformation,
                    &accounting, sizeof(accounting), NULL)) break;
            if (accounting.ActiveProcesses == 0) { clean = true; break; }
            Sleep(10);
        } while (GetTickCount64() < cleanup_end);
    }
    if (!QueryPerformanceCounter(&ended)) { clean = false; error = GetLastError(); }
    if (job && !QueryInformationJobObject(job, JobObjectExtendedLimitInformation,
            &limits, sizeof(limits), NULL)) { clean = false; error = GetLastError(); }
    if (output != INVALID_HANDLE_VALUE && !FlushFileBuffers(output)) { clean = false; error = GetLastError(); }
    if (errors != INVALID_HANDLE_VALUE && !FlushFileBuffers(errors)) { clean = false; error = GetLastError(); }
    char record[1024];
    int length = snprintf(record, sizeof(record),
        "{\"schemaVersion\":1,\"reason\":\"%s\",\"exitCode\":%lu,\"windowsError\":%lu,"
        "\"cleanupComplete\":%s,\"elapsedSeconds\":%.9f,\"userSeconds\":%.7f,\"systemSeconds\":%.7f,"
        "\"peakJobCommitBytes\":%llu,\"peakProcessCommitBytes\":%llu,"
        "\"totalProcesses\":%lu,\"activeProcesses\":%lu}\n", reason, (unsigned long)exit_code,
        (unsigned long)error, clean ? "true" : "false",
        frequency.QuadPart && started.QuadPart ? (double)(ended.QuadPart - started.QuadPart) / frequency.QuadPart : 0.0,
        accounting.TotalUserTime.QuadPart / 1e7, accounting.TotalKernelTime.QuadPart / 1e7,
        (unsigned long long)limits.PeakJobMemoryUsed, (unsigned long long)limits.PeakProcessMemoryUsed,
        (unsigned long)accounting.TotalProcesses, (unsigned long)accounting.ActiveProcesses);
    DWORD written = 0;
    bool saved = length > 0 && (size_t)length < sizeof(record) &&
        WriteFile(metrics, record, (DWORD)length, &written, NULL) && written == (DWORD)length && FlushFileBuffers(metrics);
    if (process.hThread) CloseHandle(process.hThread);
    if (process.hProcess) CloseHandle(process.hProcess);
    if (job) CloseHandle(job);
    if (attributes_ready) DeleteProcThreadAttributeList(attributes);
    if (attributes) HeapFree(GetProcessHeap(), 0, attributes);
    if (input != INVALID_HANDLE_VALUE) CloseHandle(input);
    if (output != INVALID_HANDLE_VALUE) CloseHandle(output);
    if (errors != INVALID_HANDLE_VALUE) CloseHandle(errors);
    CloseHandle(metrics); free(command);
    return saved && clean && !error && strcmp(reason, "completed") == 0 ? 0 : 1;
}
