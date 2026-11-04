#define _WIN32_WINNT 0x0a00
#include <windows.h>
#include <stddef.h>
#include <stdio.h>

_Static_assert(sizeof(void *) == 8 && sizeof(BOOL) == 4 && sizeof(DWORD) == 4 &&
    sizeof(WCHAR) == 2 && sizeof(LARGE_INTEGER) == 8, "Windows64 scalar ABI");
_Static_assert(sizeof(WIN32_STREAM_ID) == 24, "stream structure extent");
_Static_assert(offsetof(WIN32_STREAM_ID, dwStreamId) == 0 &&
    offsetof(WIN32_STREAM_ID, dwStreamAttributes) == 4 &&
    offsetof(WIN32_STREAM_ID, Size) == 8 &&
    offsetof(WIN32_STREAM_ID, dwStreamNameSize) == 16 &&
    offsetof(WIN32_STREAM_ID, cStreamName) == 20, "stream wire prefix");
_Static_assert(BACKUP_DATA == 1 && BACKUP_EA_DATA == 2 && BACKUP_ALTERNATE_DATA == 4 &&
    STREAM_NORMAL_ATTRIBUTE == 0, "stream classification");
_Static_assert((GENERIC_READ | READ_CONTROL) == 0x80020000 &&
    FILE_FLAG_OPEN_REPARSE_POINT == 0x00200000, "synchronous read access");

int main(void) {
    BOOL (WINAPI *read)(HANDLE,LPBYTE,DWORD,LPDWORD,BOOL,BOOL,LPVOID *) = BackupRead;
    BOOL (WINAPI *seek)(HANDLE,DWORD,DWORD,LPDWORD,LPDWORD,LPVOID *) = BackupSeek;
    if (!read || !seek) return 1;
    puts("windows-backup-contract=PASS pointer=64 prefix=20 BOOL=32 DWORD=32 WCHAR=16");
    return 0;
}
