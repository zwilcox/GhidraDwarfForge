#define _WIN32_WINNT 0x0a00
#include <windows.h>
#include <stddef.h>
#include <stdio.h>

/* Audited against pinned SDK headers before mapping; validate the actual CI compiler too. */
_Static_assert(sizeof(void *) == 8 && sizeof(BOOL) == 4 && sizeof(BOOLEAN) == 1 &&
    sizeof(DWORD) == 4 && sizeof(WCHAR) == 2, "Windows64 scalar ABI");
_Static_assert(sizeof(FILE_RENAME_INFO) == 24, "rename structure extent");
_Static_assert(offsetof(FILE_RENAME_INFO, ReplaceIfExists) == 0, "replace offset");
_Static_assert(offsetof(FILE_RENAME_INFO, RootDirectory) == 8, "root handle offset");
_Static_assert(offsetof(FILE_RENAME_INFO, FileNameLength) == 16, "length offset");
_Static_assert(offsetof(FILE_RENAME_INFO, FileName) == 20, "name offset");
_Static_assert(FileRenameInfo == 3 && DELETE == 0x10000 && FILE_READ_ATTRIBUTES == 0x80, "operation/access");
_Static_assert(OPEN_EXISTING == 3 && FILE_FLAG_OPEN_REPARSE_POINT == 0x200000 &&
    FILE_FLAG_BACKUP_SEMANTICS == 0x2000000, "open policy");
_Static_assert((FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE) == 7, "sharing");

int main(void) {
    HANDLE (WINAPI *create)(LPCWSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE) = CreateFileW;
    BOOL (WINAPI *set)(HANDLE,FILE_INFO_BY_HANDLE_CLASS,LPVOID,DWORD) = SetFileInformationByHandle;
    BOOL (WINAPI *close)(HANDLE) = CloseHandle;
    if (!create || !set || !close) return 1;
    puts("windows-rename-contract=PASS pointer=64 DWORD=32 WCHAR=16 name-offset=20");
    return 0;
}
