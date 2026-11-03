#define _WIN32_WINNT 0x0a00
#include <windows.h>
#include <aclapi.h>
#include <stddef.h>
#include <stdio.h>

_Static_assert(sizeof(void *) == 8 && sizeof(DWORD) == 4 && sizeof(BOOL) == 4, "Windows64 scalar ABI");
_Static_assert(sizeof(FILE_BASIC_INFO) == 40 && offsetof(FILE_BASIC_INFO, FileAttributes) == 32, "basic info");
_Static_assert(offsetof(FILE_BASIC_INFO, LastWriteTime) == 16 && offsetof(FILE_BASIC_INFO, ChangeTime) == 24, "file times");
_Static_assert(sizeof(FILE_STANDARD_INFO) == 24 && offsetof(FILE_STANDARD_INFO, NumberOfLinks) == 16 &&
    offsetof(FILE_STANDARD_INFO, EndOfFile) == 8 &&
    offsetof(FILE_STANDARD_INFO, DeletePending) == 20 && offsetof(FILE_STANDARD_INFO, Directory) == 21, "standard info");
_Static_assert(sizeof(FILE_ID_INFO) == 24 && offsetof(FILE_ID_INFO, FileId) == 8, "file identity");
_Static_assert(sizeof(FILE_ATTRIBUTE_TAG_INFO) == 8, "attribute tag info");
_Static_assert(offsetof(FILE_STREAM_INFO, StreamSize) == 8 && offsetof(FILE_STREAM_INFO, StreamName) == 24, "stream info");
_Static_assert(FileBasicInfo == 0 && FileStandardInfo == 1 && FileStreamInfo == 7 &&
    FileAttributeTagInfo == 9 && FileIdInfo == 18, "information classes");
_Static_assert(FILE_FLAG_OPEN_REPARSE_POINT == 0x00200000 && FILE_FLAG_BACKUP_SEMANTICS == 0x02000000,
    "open flags");
_Static_assert(FILE_SHARE_READ == 1 && FILE_SHARE_WRITE == 2 && FILE_SHARE_DELETE == 4 && OPEN_EXISTING == 3,
    "open disposition");
_Static_assert(GENERIC_READ == 0x80000000 && READ_CONTROL == 0x20000 && WRITE_DAC == 0x40000 &&
    WRITE_OWNER == 0x80000 && FILE_WRITE_ATTRIBUTES == 0x100 && FILE_TYPE_DISK == 1, "access rights");
_Static_assert(SE_FILE_OBJECT == 1 && OWNER_SECURITY_INFORMATION == 1 && GROUP_SECURITY_INFORMATION == 2 &&
    DACL_SECURITY_INFORMATION == 4, "security fields");
_Static_assert(sizeof(SECURITY_DESCRIPTOR_CONTROL) == 2 && SE_DACL_PROTECTED == 0x1000 && SE_SELF_RELATIVE == 0x8000,
    "security descriptor control");
_Static_assert(PROTECTED_DACL_SECURITY_INFORMATION == 0x80000000 &&
    UNPROTECTED_DACL_SECURITY_INFORMATION == 0x20000000, "DACL protection flags");

int main(void) {
    HANDLE (WINAPI *create)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = CreateFileW;
    BOOL (WINAPI *close)(HANDLE) = CloseHandle;
    DWORD (WINAPI *type)(HANDLE) = GetFileType;
    BOOL (WINAPI *get)(HANDLE, FILE_INFO_BY_HANDLE_CLASS, LPVOID, DWORD) = GetFileInformationByHandleEx;
    BOOL (WINAPI *set)(HANDLE, FILE_INFO_BY_HANDLE_CLASS, LPVOID, DWORD) = SetFileInformationByHandle;
    DWORD (WINAPI *security)(HANDLE, SE_OBJECT_TYPE, SECURITY_INFORMATION, PSID *, PSID *, PACL *, PACL *,
        PSECURITY_DESCRIPTOR *) = GetSecurityInfo;
    DWORD (WINAPI *apply)(HANDLE, SE_OBJECT_TYPE, SECURITY_INFORMATION, PSID, PSID, PACL, PACL) = SetSecurityInfo;
    BOOL (WINAPI *valid)(PSECURITY_DESCRIPTOR) = IsValidSecurityDescriptor;
    DWORD (WINAPI *length)(PSECURITY_DESCRIPTOR) = GetSecurityDescriptorLength;
    BOOL (WINAPI *control)(PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR_CONTROL, LPDWORD) = GetSecurityDescriptorControl;
    BOOL (WINAPI *sid)(PSID) = IsValidSid;
    DWORD (WINAPI *sid_length)(PSID) = GetLengthSid;
    HLOCAL (WINAPI *release)(HLOCAL) = LocalFree;
    HANDLE (WINAPI *process)(void) = GetCurrentProcess;
    BOOL (WINAPI *handles)(HANDLE, PDWORD) = GetProcessHandleCount;
    if (!create || !close || !type || !get || !set || !security || !apply || !valid || !length ||
        !control || !sid || !sid_length || !release || !process || !handles) return 1;
    puts("windows-metadata-contract=PASS pointer=64 DWORD=32 BOOL=32 basic=40 standard=24 id=24 stream-name-offset=24");
    return 0;
}
