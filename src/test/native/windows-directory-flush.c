#define _WIN32_WINNT 0x0a00
#include <windows.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>

/* Test-only mechanism experiment. Creates a NEW owned directory, never opens
 * a volume or adjusts privileges. Successful directory flush is an observation,
 * not evidence of power-loss recovery or a production filesystem contract.
 * Declarations audited against the SDK pinned in windows-directory-api.json. */
_Static_assert(sizeof(HANDLE) == 8 && sizeof(DWORD) == 4 && sizeof(BOOL) == 4 &&
    sizeof(WCHAR) == 2 && sizeof(FILE_ID_INFO) == 24, "Windows64 API layout");
_Static_assert(FileIdInfo == 18 && offsetof(FILE_ID_INFO, FileId) == 8,
    "opened directory identity");
_Static_assert(sizeof(FILE_ATTRIBUTE_TAG_INFO) == 8 && FileAttributeTagInfo == 9 &&
    offsetof(FILE_ATTRIBUTE_TAG_INFO, ReparseTag) == 4, "directory tag mapping");
_Static_assert(GENERIC_WRITE == 0x40000000 && FILE_READ_ATTRIBUTES == 0x80 &&
    FILE_ATTRIBUTE_DIRECTORY == 0x10 && FILE_ATTRIBUTE_REPARSE_POINT == 0x400 &&
    FILE_FLAG_OPEN_REPARSE_POINT == 0x200000 && FILE_FLAG_BACKUP_SEMANTICS == 0x2000000,
    "directory access and flags");

static void require(BOOL value, const char *operation) {
    if (!value) {
        fprintf(stderr, "%s failed: win32=%lu\n", operation, GetLastError());
        exit(1);
    }
}

static void close_handle(HANDLE handle) {
    require(CloseHandle(handle), "CloseHandle");
}

static HANDLE open_directory(const WCHAR *path, DWORD access) {
    return CreateFileW(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
}

static FILE_ID_INFO identity(HANDLE handle) {
    FILE_ID_INFO result;
    BY_HANDLE_FILE_INFORMATION ordinary;
    require(GetFileType(handle) == FILE_TYPE_DISK, "directory must be on disk");
    require(GetFileInformationByHandle(handle, &ordinary), "directory information");
    require((ordinary.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) ==
        FILE_ATTRIBUTE_DIRECTORY, "ordinary directory required");
    require(GetFileInformationByHandleEx(handle, FileIdInfo, &result, sizeof(result)), "directory ID");
    return result;
}

typedef struct volume_profile {
    WCHAR root[50];
    UINT drive_type;
} volume_profile;

static volume_profile volume(HANDLE handle, const FILE_ID_INFO *expected) {
    DWORD capacity = GetFinalPathNameByHandleW(handle, NULL, 0, VOLUME_NAME_GUID);
    require(capacity > 49 && capacity <= 32768, "bounded final volume path");
    WCHAR *path = calloc(capacity, sizeof(WCHAR));
    require(path != NULL, "final volume path allocation");
    DWORD length = GetFinalPathNameByHandleW(handle, path, capacity, VOLUME_NAME_GUID);
    require(length >= 49 && length < capacity && path[length] == 0 && wcslen(path) == length,
        "complete final volume path");
    require(wcsncmp(path, L"\\\\?\\Volume{", 11) == 0 && path[47] == L'}' && path[48] == L'\\',
        "final path has a volume GUID root");
    for (int i = 0; i < 36; i++) {
        BOOL separator = i == 8 || i == 13 || i == 18 || i == 23;
        require(separator ? path[11 + i] == L'-' : iswxdigit(path[11 + i]), "volume GUID syntax");
    }
    volume_profile result = {0};
    memcpy(result.root, path, 49 * sizeof(WCHAR));
    free(path);
    result.drive_type = GetDriveTypeW(result.root);
    require(result.drive_type == DRIVE_FIXED, "owned fixture requires fixed local volume");
    HANDLE root = open_directory(result.root, FILE_READ_ATTRIBUTES);
    require(root != INVALID_HANDLE_VALUE, "open resolved volume root directory");
    FILE_ID_INFO root_id = identity(root);
    close_handle(root);
    require(root_id.VolumeSerialNumber == expected->VolumeSerialNumber, "resolved root volume identity");
    return result;
}

typedef struct observation {
    DWORD access, open_error, flush_error;
    BOOL opened, flushed;
} observation;

static observation observe(const WCHAR *path, DWORD access, const FILE_ID_INFO *expected) {
    observation result = {access, 0, 0, FALSE, FALSE};
    HANDLE handle = open_directory(path, access);
    if (handle == INVALID_HANDLE_VALUE) {
        result.open_error = GetLastError();
        require(result.open_error != 0, "failed open must have an error");
        return result;
    }
    result.opened = TRUE;
    FILE_ID_INFO before = identity(handle);
    require(memcmp(&before, expected, sizeof(before)) == 0, "opened identity changed");
    result.flushed = FlushFileBuffers(handle);
    if (!result.flushed) {
        result.flush_error = GetLastError();
        require(result.flush_error != 0, "failed flush must have an error");
    }
    FILE_ID_INFO after = identity(handle);
    require(memcmp(&before, &after, sizeof(before)) == 0, "identity changed during flush");
    close_handle(handle);
    return result;
}

static void print_observation(observation value) {
    printf("{\"access\":%lu,\"opened\":%s,\"openError\":%lu,\"flushed\":%s,\"flushError\":%lu}",
        value.access, value.opened ? "true" : "false", value.open_error,
        value.flushed ? "true" : "false", value.flush_error);
}

int wmain(int argc, WCHAR **argv) {
    DWORD (WINAPI *final_path_contract)(HANDLE, LPWSTR, DWORD, DWORD) = GetFinalPathNameByHandleW;
    UINT (WINAPI *drive_type_contract)(LPCWSTR) = GetDriveTypeW;
    _Static_assert(sizeof(UINT) == 4 && VOLUME_NAME_GUID == 1 && DRIVE_FIXED == 3,
        "opened volume profile ABI");
    BOOL (WINAPI *flush_contract)(HANDLE) = FlushFileBuffers;
    BOOL (WINAPI *volume_contract)(HANDLE,LPWSTR,DWORD,LPDWORD,LPDWORD,LPDWORD,LPWSTR,DWORD) =
        GetVolumeInformationByHandleW;
    HANDLE (WINAPI *open_contract)(LPCWSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE) = CreateFileW;
    BOOL (WINAPI *information_contract)(HANDLE,FILE_INFO_BY_HANDLE_CLASS,LPVOID,DWORD) = GetFileInformationByHandleEx;
    DWORD (WINAPI *type_contract)(HANDLE) = GetFileType;
    BOOL (WINAPI *close_contract)(HANDLE) = CloseHandle;
    require(flush_contract != NULL && volume_contract != NULL && open_contract != NULL &&
        information_contract != NULL && type_contract != NULL && close_contract != NULL &&
        final_path_contract != NULL && drive_type_contract != NULL, "API signatures");
    BOOL volume_requested = argc == 3 && !wcscmp(argv[1], L"--volume-profile");
    require(argc == 2 || volume_requested, "one new owned directory and optional volume profile required");
    const WCHAR *owned = argv[argc - 1];
    require(wcslen(owned) < 20000, "owned directory path bound");
    require(CreateDirectoryW(owned, NULL), "exclusive directory creation");
    WCHAR child[22000], renamed[22000];
    require(swprintf(child, 22000, L"%ls\\before", owned) > 0, "child path");
    require(swprintf(renamed, 22000, L"%ls\\after", owned) > 0, "renamed path");
    HANDLE handle = open_directory(owned, FILE_READ_ATTRIBUTES);
    require(handle != INVALID_HANDLE_VALUE, "open owned directory");
    FILE_ID_INFO expected = identity(handle);
    WCHAR fs[128] = {0};
    DWORD serial, maximum, flags;
    require(GetVolumeInformationByHandleW(handle, NULL, 0, &serial, &maximum, &flags, fs, 128),
        "opened volume facts");
    volume_profile expected_volume = {0};
    if (volume_requested) expected_volume = volume(handle, &expected);
    close_handle(handle);

    HANDLE file = CreateFileW(child, GENERIC_READ | GENERIC_WRITE | DELETE, 7, NULL,
        CREATE_NEW, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    require(file != INVALID_HANDLE_VALUE, "exclusive child creation");
    const BYTE bytes[] = {0, 0xff, 0x42, 0x0a, 0x19};
    DWORD written;
    require(WriteFile(file, bytes, sizeof(bytes), &written, NULL) && written == sizeof(bytes), "child write");
    require(FlushFileBuffers(file), "positive ordinary file flush control");
    const DWORD access[] = {FILE_READ_ATTRIBUTES, GENERIC_WRITE | FILE_READ_ATTRIBUTES, GENERIC_READ | GENERIC_WRITE};
    observation before[3], after[3];
    for (int i = 0; i < 3; i++) before[i] = observe(owned, access[i], &expected);

    DWORD name_bytes = (DWORD)(wcslen(renamed) * sizeof(WCHAR));
    DWORD rename_size = (DWORD)offsetof(FILE_RENAME_INFO, FileName) + name_bytes;
    FILE_RENAME_INFO *rename = calloc(1, rename_size);
    require(rename != NULL, "rename allocation");
    rename->FileNameLength = name_bytes;
    memcpy(rename->FileName, renamed, name_bytes);
    require(SetFileInformationByHandle(file, FileRenameInfo, rename, rename_size), "owned child rename");
    free(rename);
    require(FlushFileBuffers(file), "ordinary file flush after rename");
    close_handle(file);
    require(GetFileAttributesW(child) == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND,
        "old owned name removed");
    file = CreateFileW(renamed, GENERIC_READ, 7, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    require(file != INVALID_HANDLE_VALUE, "open renamed read-only control");
    BYTE readback[sizeof(bytes)];
    DWORD read;
    require(ReadFile(file, readback, sizeof(readback), &read, NULL) && read == sizeof(bytes) &&
        memcmp(bytes, readback, sizeof(bytes)) == 0, "renamed bytes");
    BOOL read_flush = FlushFileBuffers(file);
    DWORD read_error = read_flush ? 0 : GetLastError();
    require(!read_flush && read_error == ERROR_ACCESS_DENIED, "read-only file negative flush control");
    close_handle(file);
    for (int i = 0; i < 3; i++) after[i] = observe(owned, access[i], &expected);

    DWORD start_handles, end_handles;
    require(GetProcessHandleCount(GetCurrentProcess(), &start_handles), "initial handle count");
    for (int cycle = 0; cycle < 128; cycle++) {
        if (volume_requested) {
            HANDLE selected = open_directory(owned, FILE_READ_ATTRIBUTES);
            require(selected != INVALID_HANDLE_VALUE, "repeated volume directory open");
            volume_profile current_volume = volume(selected, &expected);
            close_handle(selected);
            require(current_volume.drive_type == expected_volume.drive_type &&
                wcscmp(current_volume.root, expected_volume.root) == 0, "volume profile changed");
        }
        for (int i = 0; i < 3; i++) {
            observation current = observe(owned, access[i], &expected);
            require(current.opened == after[i].opened && current.flushed == after[i].flushed &&
                current.open_error == after[i].open_error && current.flush_error == after[i].flush_error,
                "inconsistent repeated directory observation");
        }
        require(GetProcessHandleCount(GetCurrentProcess(), &end_handles), "final handle count");
        require(start_handles == end_handles, "directory handle leak");
    }
    printf("{\"status\":\"OBSERVED\",\"volume128\":\"%016llx\",\"fileId128\":\"",
        (unsigned long long)expected.VolumeSerialNumber);
    for (size_t i = 0; i < sizeof(expected.FileId.Identifier); i++) printf("%02x", expected.FileId.Identifier[i]);
    printf("\",\"fileSystemUtf16\":\"");
    for (size_t i = 0; fs[i] != 0; i++) printf("%04x", (unsigned int)fs[i]);
    if (volume_requested) {
        printf("\",\"volumeRootUtf16\":\"");
        for (size_t i = 0; expected_volume.root[i] != 0; i++) printf("%04x", (unsigned int)expected_volume.root[i]);
        printf("\",\"driveType\":%u,\"volumeRootIdentityMatched\":true,\"volumeProfileCycles\":128,",
            expected_volume.drive_type);
    }
    else printf("\",");
    printf("\"volumeSerial\":%lu,\"maximumNameUnits\":%lu,\"fileSystemFlags\":%lu,\"beforeRename\":[",
        serial, maximum, flags);
    for (int i = 0; i < 3; i++) { if (i) putchar(','); print_observation(before[i]); }
    printf("],\"afterRename\":[");
    for (int i = 0; i < 3; i++) { if (i) putchar(','); print_observation(after[i]); }
    printf("],\"fileFlush\":true,\"readOnlyFileError\":%lu,\"handleCycles\":128,"
        "\"handlesBefore\":%lu,\"handlesAfter\":%lu,\"powerLossRecoveryProven\":false}\n",
        read_error, start_handles, end_handles);
    return 0;
}
