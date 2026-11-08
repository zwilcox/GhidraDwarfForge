#define _WIN32_WINNT 0x0a00
#include <windows.h>
#include <winternl.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

/* Test only: independent native EA creation/query, not the BackupRead API under test. */
NTSYSAPI NTSTATUS NTAPI NtSetEaFile(HANDLE,PIO_STATUS_BLOCK,PVOID,ULONG);
NTSYSAPI NTSTATUS NTAPI NtQueryEaFile(HANDLE,PIO_STATUS_BLOCK,PVOID,ULONG,BOOLEAN,PVOID,ULONG,PULONG,BOOLEAN);
_Static_assert(sizeof(IO_STATUS_BLOCK) == 16 && offsetof(IO_STATUS_BLOCK, Information) == 8,
    "IO status ABI");
_Static_assert(offsetof(FILE_FULL_EA_INFORMATION, EaName) == 8 &&
    sizeof(BOOLEAN) == 1 && sizeof(NTSTATUS) == 4, "EA record ABI");

static int backup_once(const wchar_t *path, int cancel) {
    HANDLE handle = CreateFileW(path, GENERIC_READ | READ_CONTROL, 7, NULL, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (handle == INVALID_HANDLE_VALUE) return 1;
    LPVOID context = NULL;
    union { WIN32_STREAM_ID aligned; BYTE bytes[65536]; } data;
    DWORD count = 0;
    int failed = 0;
    for (;;) {
        if (!BackupRead(handle, data.bytes, 20, &count, FALSE, FALSE, &context)) { failed = 2; break; }
        if (count == 0) break;
        if (count != 20 || data.aligned.dwStreamNameSize > sizeof(data.bytes)) { failed = 3; break; }
        if (cancel) break;
        LARGE_INTEGER size = data.aligned.Size;
        DWORD names = data.aligned.dwStreamNameSize;
        if (names && (!BackupRead(handle, data.bytes, names, &count, FALSE, FALSE, &context) || count != names)) {
            failed = 4; break;
        }
        DWORD low = 0, high = 0;
        if (size.QuadPart && (!BackupSeek(handle, size.LowPart, (DWORD)size.HighPart, &low, &high, &context) ||
                low != size.LowPart || high != (DWORD)size.HighPart)) { failed = 5; break; }
    }
    if (!BackupRead(handle, NULL, 0, &count, TRUE, FALSE, &context)) failed = 6;
    if (!CloseHandle(handle)) failed = 7;
    return failed;
}

static int backup_lifetime(const wchar_t *path) {
    if (backup_once(path, 0) || backup_once(path, 1)) return 10;
    DWORD before = 0, after = 0;
    if (!GetProcessHandleCount(GetCurrentProcess(), &before)) return 11;
    printf("{\"baseline\":%lu,\"samples\":[", before);
    for (int i = 0; i < 128; i++) {
        if (backup_once(path, 0) || backup_once(path, 1)) return 12;
        if (!GetProcessHandleCount(GetCurrentProcess(), &after)) return 13;
        printf("%s%lu", i ? "," : "", after);
    }
    printf("],\"after\":%lu}\n", after);
    return after == before ? 0 : 14;
}

int wmain(int argc, wchar_t **argv) {
    if (argc == 3 && !wcscmp(argv[1], L"backup-lifetime")) return backup_lifetime(argv[2]);
    if (argc != 3 || (wcscmp(argv[1], L"set") && wcscmp(argv[1], L"query"))) return 2;
    int setting = !wcscmp(argv[1], L"set");
    HANDLE handle = CreateFileW(argv[2], FILE_READ_EA | (setting ? FILE_WRITE_EA : 0),
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (handle == INVALID_HANDLE_VALUE) { fprintf(stderr, "CreateFile=%lu\n", GetLastError()); return 3; }
    union { FILE_FULL_EA_INFORMATION aligned; unsigned char bytes[4096]; } data = {0};
    IO_STATUS_BLOCK status = {0};
    NTSTATUS result;
    if (setting) {
        const char name[] = "FORGE_TEST";
        const unsigned char value[] = {0x00,0xff,0x42,0x0a,0x19};
        data.aligned.EaNameLength = sizeof(name) - 1;
        data.aligned.EaValueLength = sizeof(value);
        memcpy(data.bytes + 8, name, sizeof(name));
        memcpy(data.bytes + 8 + sizeof(name), value, sizeof(value));
        result = NtSetEaFile(handle, &status, data.bytes, 8 + sizeof(name) + sizeof(value));
        if (result != 0) { fprintf(stderr, "NtSetEaFile=%08lx\n", (unsigned long)result); CloseHandle(handle); return 4; }
        memset(&data, 0, sizeof(data));
    }
    result = NtQueryEaFile(handle, &status, data.bytes, sizeof(data.bytes), FALSE, NULL, 0, NULL, TRUE);
    if (!CloseHandle(handle)) return 5;
    if ((ULONG)result == 0xc0000052UL) { puts("{\"eaBytes\":null}"); return setting ? 6 : 0; }
    if (result != 0 || status.Information < 8 || status.Information > sizeof(data.bytes)) {
        fprintf(stderr, "NtQueryEaFile=%08lx bytes=%llu\n", (unsigned long)result,
            (unsigned long long)status.Information); return 7;
    }
    printf("{\"eaBytes\":\"");
    for (ULONG_PTR i = 0; i < status.Information; i++) printf("%02x", data.bytes[i]);
    puts("\"}");
    return 0;
}
