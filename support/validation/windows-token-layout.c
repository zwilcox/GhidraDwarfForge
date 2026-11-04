#include <windows.h>
#include <stddef.h>

/* Compile with the Windows x64 toolchain; no process or token is modified. */
_Static_assert(sizeof(HANDLE) == 8, "Windows x64 handles required");
_Static_assert(sizeof(BOOL) == 4 && sizeof(DWORD) == 4, "fixed-width Win32 scalars");
_Static_assert(sizeof(LUID) == 8, "LUID layout");
_Static_assert(sizeof(LUID_AND_ATTRIBUTES) == 12, "LUID_AND_ATTRIBUTES layout");
_Static_assert(offsetof(LUID_AND_ATTRIBUTES, Attributes) == 8, "attribute offset");
_Static_assert(sizeof(TOKEN_PRIVILEGES) == 16, "single-entry token privilege size");
_Static_assert(offsetof(TOKEN_PRIVILEGES, Privileges) == 4, "privilege array offset");
_Static_assert(TOKEN_QUERY == 8 && TOKEN_ADJUST_PRIVILEGES == 32, "token access mask");
_Static_assert(TokenPrivileges == 3, "token information class");
_Static_assert(SE_PRIVILEGE_ENABLED == 2, "enable mask");
_Static_assert(ERROR_INSUFFICIENT_BUFFER == 122 && ERROR_NOT_ALL_ASSIGNED == 1300, "Win32 errors");
_Static_assert(__builtin_types_compatible_p(__typeof__(&AdjustTokenPrivileges),
    BOOL (WINAPI *)(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD)), "adjust signature");
_Static_assert(__builtin_types_compatible_p(__typeof__(&GetTokenInformation),
    BOOL (WINAPI *)(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD)), "query signature");
_Static_assert(__builtin_types_compatible_p(__typeof__(&OpenProcessToken),
    BOOL (WINAPI *)(HANDLE, DWORD, PHANDLE)), "open signature");
_Static_assert(__builtin_types_compatible_p(__typeof__(&LookupPrivilegeValueW),
    BOOL (WINAPI *)(LPCWSTR, LPCWSTR, PLUID)), "lookup signature");
