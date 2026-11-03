#define _WIN32_WINNT 0x0a00
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

/* Test-only fixture/observer, never installed as a production helper. Changes
 * only its own process token and, in create mode, one exclusively created file.
 * The original SeSecurityPrivilege enabled state is restored before success.
 * No elevation, impersonation, owner/DACL changes or target replacement. */
_Static_assert(sizeof(HANDLE) == 8 && sizeof(BOOL) == 4 && sizeof(DWORD) == 4 &&
    sizeof(WCHAR) == 2 && sizeof(SECURITY_DESCRIPTOR_CONTROL) == 2, "Windows64 ABI");
_Static_assert(BACKUP_SECURITY_INFORMATION == 0x10000 && ACCESS_SYSTEM_SECURITY == 0x1000000 &&
    READ_CONTROL == 0x20000 && SACL_SECURITY_INFORMATION == 8 && LABEL_SECURITY_INFORMATION == 16,
    "complete security information/access");
_Static_assert(sizeof(ACL) == 8 && sizeof(ACE_HEADER) == 4 &&
    SYSTEM_AUDIT_ACE_TYPE == 2 && SYSTEM_MANDATORY_LABEL_ACE_TYPE == 17, "audit/label layout");

/* Retain BACKUP (all parts), explicitly selecting each SDK component as well.
 * Native run41623565789 proves BACKUP alone fails in GetSecurityInfo despite
 * sufficient rights, while this union succeeds. The independent path observer
 * deliberately continues using BACKUP alone. */
#define COMPLETE_SECURITY_FIELDS (BACKUP_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION | \
    GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION | \
    LABEL_SECURITY_INFORMATION | ATTRIBUTE_SECURITY_INFORMATION | SCOPE_SECURITY_INFORMATION | \
    PROCESS_TRUST_LABEL_SECURITY_INFORMATION | ACCESS_FILTER_SECURITY_INFORMATION)
_Static_assert(COMPLETE_SECURITY_FIELDS == 0x101ff, "complete descriptor query flags");

_Static_assert(sizeof(LUID) == 8 && sizeof(TOKEN_PRIVILEGES) == 16 &&
    offsetof(TOKEN_PRIVILEGES, Privileges) == 4 && offsetof(LUID_AND_ATTRIBUTES, Attributes) == 8,
    "isolated Java own-token fixture layout");
_Static_assert((SE_SACL_PRESENT | SE_SACL_DEFAULTED | SE_SACL_AUTO_INHERIT_REQ |
    SE_SACL_AUTO_INHERITED | SE_SACL_PROTECTED) == 0x2a30 && SE_RM_CONTROL_VALID == 0x4000,
    "complete attachment security control mask");

static void require(BOOL value, const char *operation) {
    if (!value) { fprintf(stderr, "%s failed: win32=%lu\n", operation, GetLastError()); exit(1); }
}

static DWORD attributes(HANDLE token, LUID luid) {
    DWORD bytes = 0;
    require(!GetTokenInformation(token, TokenPrivileges, NULL, 0, &bytes) &&
        GetLastError() == ERROR_INSUFFICIENT_BUFFER && bytes >= sizeof(TOKEN_PRIVILEGES) &&
        bytes <= 1024 * 1024, "token buffer bound");
    TOKEN_PRIVILEGES *data = malloc(bytes);
    require(data != NULL, "token allocation");
    require(GetTokenInformation(token, TokenPrivileges, data, bytes, &bytes), "token privileges");
    require(data->PrivilegeCount <= (bytes - offsetof(TOKEN_PRIVILEGES, Privileges)) /
        sizeof(LUID_AND_ATTRIBUTES), "token privilege count");
    DWORD found = 0;
    BOOL present = FALSE;
    for (DWORD i = 0; i < data->PrivilegeCount; i++) {
        if (data->Privileges[i].Luid.LowPart == luid.LowPart &&
                data->Privileges[i].Luid.HighPart == luid.HighPart) {
            require(!present, "duplicate security privilege");
            found = data->Privileges[i].Attributes;
            present = TRUE;
        }
    }
    free(data);
    require(present, "test runner lacks SeSecurityPrivilege; cannot seed full-security fixture");
    return found;
}

static void enable(HANDLE token, LUID luid, BOOL enabled) {
    TOKEN_PRIVILEGES state = {0};
    state.PrivilegeCount = 1;
    state.Privileges[0].Luid = luid;
    state.Privileges[0].Attributes = enabled ? SE_PRIVILEGE_ENABLED : 0;
    SetLastError(ERROR_SUCCESS);
    require(AdjustTokenPrivileges(token, FALSE, &state, 0, NULL, NULL) &&
        GetLastError() == ERROR_SUCCESS, "scoped security privilege adjustment");
    require(((attributes(token, luid) & SE_PRIVILEGE_ENABLED) != 0) == enabled, "privilege readback");
}

typedef struct security_snapshot {
    SECURITY_DESCRIPTOR_CONTROL control;
    BOOL present, defaulted;
    DWORD bytes, audits, labels;
    BYTE acl[65536];
} security_snapshot;

static void snapshot(PSECURITY_DESCRIPTOR descriptor, security_snapshot *result) {
    memset(result, 0, sizeof(*result));
    require(IsValidSecurityDescriptor(descriptor), "valid security descriptor");
    DWORD revision = 0, length = GetSecurityDescriptorLength(descriptor);
    require(length >= SECURITY_DESCRIPTOR_MIN_LENGTH && length <= 1024 * 1024, "descriptor length");
    require(GetSecurityDescriptorControl(descriptor, &result->control, &revision) && revision == 1 &&
        (result->control & SE_SELF_RELATIVE), "self-relative descriptor control");
    PACL acl = NULL;
    require(GetSecurityDescriptorSacl(descriptor, &result->present, &acl, &result->defaulted), "SACL read");
    if (acl) {
        require(result->present && IsValidAcl(acl) && acl->AclSize >= sizeof(ACL) &&
            acl->AceCount <= 4096, "SACL validity");
        result->bytes = acl->AclSize;
        memcpy(result->acl, acl, result->bytes);
        for (DWORD i = 0; i < acl->AceCount; i++) {
            ACE_HEADER *ace = NULL;
            require(GetAce(acl, i, (PVOID *)&ace), "SACL ACE");
            size_t offset = (BYTE *)ace - (BYTE *)acl;
            require(offset <= result->bytes - sizeof(ACE_HEADER) && ace->AceSize >= sizeof(ACE_HEADER) &&
                ace->AceSize <= result->bytes - offset, "SACL ACE bound");
            if (ace->AceType == SYSTEM_AUDIT_ACE_TYPE) result->audits++;
            if (ace->AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE) result->labels++;
        }
    }
}

static const WCHAR *fixture_path;
static const char *query_phase = "not-started";
static DWORD requested_open_access;

static void diagnose_query(HANDLE handle, DWORD fields, DWORD error) {
    DWORD required = 0;
    QuerySecurityAccessMask(fields, &required);
    fprintf(stderr, "security-query phase=%s fields=%08lx required=%08lx opened=%08lx error=%lu\n",
        query_phase, fields, required, requested_open_access, error);
    const DWORD variants[] = {7, 8, 16, 0x1f, 0x1ff, 0x10000, 0x1001f, 0x101ff};
    for (size_t i = 0; i < sizeof(variants) / sizeof(variants[0]); i++) {
        PSECURITY_DESCRIPTOR descriptor = NULL;
        DWORD value = GetSecurityInfo(handle, SE_FILE_OBJECT, variants[i], NULL, NULL, NULL, NULL, &descriptor);
        QuerySecurityAccessMask(variants[i], &required);
        DWORD needed = 0;
        BOOL path_result = GetFileSecurityW(fixture_path, variants[i], NULL, 0, &needed);
        DWORD path_error = path_result ? 0 : GetLastError();
        fprintf(stderr, "security-variant fields=%08lx required=%08lx handleError=%lu pathError=%lu pathBytes=%lu\n",
            variants[i], required, value, path_error, needed);
        if (descriptor) require(LocalFree(descriptor) == NULL, "diagnostic descriptor release");
    }
}

static void opened_snapshot(HANDLE handle, DWORD fields, security_snapshot *result) {
    PSECURITY_DESCRIPTOR descriptor = NULL;
    DWORD error = GetSecurityInfo(handle, SE_FILE_OBJECT, fields, NULL, NULL, NULL, NULL, &descriptor);
    if (error) { diagnose_query(handle, fields, error); SetLastError(error); require(FALSE, "GetSecurityInfo"); }
    snapshot(descriptor, result);
    require(LocalFree(descriptor) == NULL, "security descriptor release");
}

static void path_snapshot(const WCHAR *path, security_snapshot *result) {
    DWORD bytes = 0;
    require(!GetFileSecurityW(path, BACKUP_SECURITY_INFORMATION, NULL, 0, &bytes) &&
        GetLastError() == ERROR_INSUFFICIENT_BUFFER && bytes >= SECURITY_DESCRIPTOR_MIN_LENGTH &&
        bytes <= 1024 * 1024, "path security buffer bound");
    PSECURITY_DESCRIPTOR descriptor = malloc(bytes);
    require(descriptor != NULL, "path security allocation");
    require(GetFileSecurityW(path, BACKUP_SECURITY_INFORMATION, descriptor, bytes, &bytes), "GetFileSecurityW");
    snapshot(descriptor, result);
    free(descriptor);
}

static void kernel_snapshot(HANDLE handle, security_snapshot *result) {
    DWORD bytes = 0;
    require(!GetKernelObjectSecurity(handle, BACKUP_SECURITY_INFORMATION, NULL, 0, &bytes) &&
        GetLastError() == ERROR_INSUFFICIENT_BUFFER && bytes >= SECURITY_DESCRIPTOR_MIN_LENGTH &&
        bytes <= 1024 * 1024, "kernel security buffer bound");
    DWORD capacity = bytes;
    PSECURITY_DESCRIPTOR descriptor = malloc(capacity);
    require(descriptor != NULL, "kernel security allocation");
    require(GetKernelObjectSecurity(handle, BACKUP_SECURITY_INFORMATION, descriptor, capacity, &bytes) &&
        bytes <= capacity, "GetKernelObjectSecurity");
    snapshot(descriptor, result);
    free(descriptor);
}

static void same(const security_snapshot *a, const security_snapshot *b) {
    require(a->control == b->control && a->present == b->present && a->defaulted == b->defaulted &&
        a->bytes == b->bytes && !memcmp(a->acl, b->acl, a->bytes), "independent complete SACL observations agree");
}

static void print_snapshot(FILE *out, const security_snapshot *value) {
    fprintf(out, "{\"control\":%u,\"saclPresent\":%s,\"saclDefaulted\":%s,\"auditAces\":%lu,"
        "\"labelAces\":%lu,\"saclHex\":", (unsigned int)value->control, value->present ? "true" : "false",
        value->defaulted ? "true" : "false", value->audits, value->labels);
    if (value->bytes) {
        fputc('"', out);
        for (DWORD i = 0; i < value->bytes; i++) fprintf(out, "%02x", value->acl[i]);
        fputc('"', out);
    } else fprintf(out, "null");
    fputc('}', out);
}

int wmain(int argc, WCHAR **argv) {
    BOOL (WINAPI *read_kernel)(HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, DWORD, LPDWORD) = GetKernelObjectSecurity;
    (void)read_kernel;
    BOOL (WINAPI *read_sacl)(PSECURITY_DESCRIPTOR, LPBOOL, PACL *, LPBOOL) = GetSecurityDescriptorSacl;
    BOOL (WINAPI *valid_acl)(PACL) = IsValidAcl;
    BOOL (WINAPI *adjust_token)(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD) = AdjustTokenPrivileges;
    (void)read_sacl; (void)valid_acl; (void)adjust_token;

    require(argc == 3 && (!wcscmp(argv[1], L"create") || !wcscmp(argv[1], L"read") || !wcscmp(argv[1], L"observe")), "mode and owned path required");
    BOOL creating = !wcscmp(argv[1], L"create");
    fixture_path = argv[2];
    if (creating) {
        HANDLE file = CreateFileW(argv[2], GENERIC_WRITE, 7, NULL, CREATE_NEW, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
        require(file != INVALID_HANDLE_VALUE, "exclusive security fixture creation");
        const BYTE payload[] = {0x41, 0, 0xff, 0x19, 0x0a};
        DWORD written;
        require(WriteFile(file, payload, sizeof(payload), &written, NULL) && written == sizeof(payload), "fixture bytes");
        require(FlushFileBuffers(file), "fixture flush");
        require(CloseHandle(file), "fixture close");
    }
    HANDLE token = NULL;
    LUID luid;
    require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &token), "open own token");
    require(LookupPrivilegeValueW(NULL, L"SeSecurityPrivilege", &luid), "security privilege LUID");
    DWORD original_attributes = attributes(token, luid);
    enable(token, luid, FALSE);
    HANDLE inaccessible = CreateFileW(argv[2], READ_CONTROL | ACCESS_SYSTEM_SECURITY, 7, NULL,
        OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    DWORD open_error = inaccessible == INVALID_HANDLE_VALUE ? GetLastError() : 0;
    if (inaccessible != INVALID_HANDLE_VALUE) require(CloseHandle(inaccessible), "unexpected handle cleanup");
    require(open_error == ERROR_PRIVILEGE_NOT_HELD, "disabled privilege must refuse full-security open");
    HANDLE ordinary = CreateFileW(argv[2], READ_CONTROL, 7, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    require(ordinary != INVALID_HANDLE_VALUE, "ordinary control open");
    PSECURITY_DESCRIPTOR denied = NULL;
    DWORD query_error = GetSecurityInfo(ordinary, SE_FILE_OBJECT, COMPLETE_SECURITY_FIELDS,
        NULL, NULL, NULL, NULL, &denied);
    if (denied) require(LocalFree(denied) == NULL, "denied descriptor cleanup");
    SetLastError(query_error);
    require(query_error == ERROR_ACCESS_DENIED, "ordinary handle must refuse complete security");
    DWORD denied_bytes = 0;
    PSECURITY_DESCRIPTOR denied_kernel = malloc(1024 * 1024);
    require(denied_kernel != NULL, "denied kernel buffer allocation");
    BOOL kernel_denied = GetKernelObjectSecurity(ordinary, BACKUP_SECURITY_INFORMATION,
        denied_kernel, 1024 * 1024, &denied_bytes);
    DWORD kernel_query_error = kernel_denied ? 0 : GetLastError();
    free(denied_kernel);
    require(!kernel_denied && kernel_query_error == ERROR_ACCESS_DENIED,
        "ordinary handle must refuse complete kernel security");
    require(CloseHandle(ordinary), "ordinary control close");

    enable(token, luid, TRUE);
    DWORD query_access = 0;
    QuerySecurityAccessMask(BACKUP_SECURITY_INFORMATION, &query_access);
    requested_open_access = READ_CONTROL | ACCESS_SYSTEM_SECURITY | query_access | (creating ? WRITE_OWNER : 0);
    HANDLE complete = CreateFileW(argv[2], requested_open_access, 7, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    require(complete != INVALID_HANDLE_VALUE, "complete-security open");
    security_snapshot before, full, independent, visible;
    query_phase = "before-fixture";
    kernel_snapshot(complete, &before);
    if (creating) {
        PSECURITY_DESCRIPTOR seed = NULL;
        require(ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"S:P(AU;SA;FR;;;WD)(ML;;NW;;;ME)", SDDL_REVISION_1, &seed, NULL), "audit/label seed");
        BOOL present, defaulted;
        PACL sacl = NULL;
        require(GetSecurityDescriptorSacl(seed, &present, &sacl, &defaulted) && present && sacl, "seed SACL");
        DWORD error = SetSecurityInfo(complete, SE_FILE_OBJECT,
            SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION | PROTECTED_SACL_SECURITY_INFORMATION,
            NULL, NULL, NULL, sacl);
        require(LocalFree(seed) == NULL, "seed descriptor release");
        if (error) { SetLastError(error); require(FALSE, "owned audit/label fixture"); }
    }
    query_phase = "after-audit-label";
    kernel_snapshot(complete, &full);
    path_snapshot(argv[2], &independent);
    same(&full, &independent);
    // Retain the high-level API as a diagnostic, never as canonical input.
    // Its extra SACL_PROTECTED bit on absent SACLs was independently observed.
    security_snapshot high_level;
    opened_snapshot(complete, COMPLETE_SECURITY_FIELDS, &high_level);
    require(high_level.present == full.present && high_level.defaulted == full.defaulted &&
        high_level.bytes == full.bytes && !memcmp(high_level.acl, full.acl, full.bytes) &&
        (high_level.control == full.control || (!full.present &&
            (high_level.control ^ full.control) == SE_SACL_PROTECTED)),
        "high-level diagnostic differs beyond observed absent-SACL protection behavior");
    if (wcscmp(argv[1], L"observe") && (!full.present || full.audits != 1 || full.labels != 1)) {
        fprintf(stderr, "whole descriptor control=%04x present=%d audit=%lu label=%lu bytes=%lu\n",
            (unsigned int)full.control, full.present, full.audits, full.labels, full.bytes);
        require(FALSE, "whole descriptor must include audit and label");
    }
    query_phase = "ordinary-visible";
    opened_snapshot(complete, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &visible);
    require(!visible.present && !visible.bytes, "ordinary descriptor must not invent SACL visibility");
    DWORD baseline, after;
    require(GetProcessHandleCount(GetCurrentProcess(), &baseline), "initial security handles");
    query_phase = "repeated-whole-security";
    for (int i = 0; i < 128; i++) {
        kernel_snapshot(complete, &independent); same(&full, &independent);
        path_snapshot(argv[2], &independent); same(&full, &independent);
        require(GetProcessHandleCount(GetCurrentProcess(), &after) && after == baseline, "security handle cleanup");
    }
    require(CloseHandle(complete), "complete security close");
    enable(token, luid, (original_attributes & SE_PRIVILEGE_ENABLED) != 0);
    DWORD restored_attributes = attributes(token, luid);
    require(CloseHandle(token), "own token close");
    printf("{\"status\":\"OBSERVED\",\"created\":%s,\"disabledPrivilegeOpenError\":%lu,"
        "\"insufficientHandleQueryError\":%lu,\"initialPrivilegeAttributes\":%lu,"
        "\"restoredPrivilegeAttributes\":%lu,\"before\":", creating ? "true" : "false", open_error,
        query_error, original_attributes, restored_attributes);
    print_snapshot(stdout, &before); printf(",\"complete\":"); print_snapshot(stdout, &full);
    printf(",\"highLevel\":"); print_snapshot(stdout, &high_level);
    printf(",\"canonicalApi\":\"GetKernelObjectSecurity\",\"insufficientKernelQueryError\":%lu", kernel_query_error);
    printf(",\"ordinary\":"); print_snapshot(stdout, &visible);
    printf(",\"queryFields\":%lu,\"queryAccess\":%lu,\"openedAccess\":%lu,\"handleCycles\":128,\"handlesBefore\":%lu,\"handlesAfter\":%lu}\n", (DWORD)BACKUP_SECURITY_INFORMATION, query_access, requested_open_access, baseline, after);
    return 0;
}
