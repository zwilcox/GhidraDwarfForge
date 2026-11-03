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

int wmain(int argc, wchar_t **argv) {
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
