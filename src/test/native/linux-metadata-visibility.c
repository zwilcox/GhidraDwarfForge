#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

/* Standalone evidence only. Never opens an existing target or changes a token
 * outside its owned child. The caller explicitly selects a fresh test root. */
static const char marker[] = "trusted.ghidra_dwarf_forge_visibility";

static int listed(int fd) {
    char names[65536];
    ssize_t count = flistxattr(fd, names, sizeof(names));
    if (count < 0) return -1;
    for (size_t offset = 0; offset < (size_t) count;) {
        size_t length = strnlen(names + offset, (size_t) count - offset);
        if (length == (size_t) count - offset) return -1;
        if (!strcmp(names + offset, marker)) return 1;
        offset += length + 1;
    }
    return 0;
}

struct child_result {
    int capset_error;
    int read_error;
    int marker_listed;
    int identity_unchanged;
};

int main(int argc, char **argv) {
    if (argc != 3 || (strcmp(argv[1], "--unprivileged") && strcmp(argv[1], "--privileged"))) {
        fprintf(stderr, "usage: %s --unprivileged|--privileged existing-test-parent\n", argv[0]);
        return 64;
    }
    int privileged = !strcmp(argv[1], "--privileged");
    char directory[4096];
    int length = snprintf(directory, sizeof(directory), "%s/visibility.XXXXXX", argv[2]);
    if (length < 0 || (size_t) length >= sizeof(directory) || !mkdtemp(directory)) {
        perror("owned visibility directory");
        return 1;
    }
    int parent = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int fd = parent < 0 ? -1 : openat(parent, "canary", O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    int status = 1;
    struct stat before, after;
    struct statfs filesystem;
    unsigned char expected[32], actual[32];
    if (fd < 0 || fstat(fd, &before) || fstatfs(fd, &filesystem) ||
            getrandom(expected, sizeof(expected), 0) != (ssize_t) sizeof(expected)) {
        perror("owned canary setup");
        goto cleanup;
    }
    errno = 0;
    int set_result = fsetxattr(fd, marker, expected, sizeof(expected), XATTR_CREATE);
    int set_error = errno;
    if (!privileged) {
        errno = 0;
        ssize_t bytes = fgetxattr(fd, marker, actual, sizeof(actual));
        int read_error = errno;
        int visible = listed(fd);
        if (set_result != -1 || set_error != EPERM || bytes != -1 || read_error != ENODATA || visible != 0) {
            fprintf(stderr, "unexpected unprivileged observation: set=%d/%d read=%zd/%d listed=%d\n",
                set_result, set_error, bytes, read_error, visible);
            goto cleanup;
        }
        printf("{\"mode\":\"unprivileged\",\"setErrno\":%d,\"getErrno\":%d,\"listed\":%d,\"filesystemType\":%lu}\n",
            set_error, read_error, visible, (unsigned long) filesystem.f_type);
        status = 0;
        goto cleanup;
    }
    if (set_result || fgetxattr(fd, marker, actual, sizeof(actual)) != (ssize_t) sizeof(actual) ||
            memcmp(actual, expected, sizeof(actual)) || listed(fd) != 1) {
        fprintf(stderr, "authorized canary creation/read/list failed: set=%d errno=%d\n", set_result, set_error);
        goto cleanup;
    }
    int channel[2];
    if (pipe2(channel, O_CLOEXEC)) { perror("result pipe"); goto cleanup; }
    pid_t child = fork();
    if (child < 0) { close(channel[0]); close(channel[1]); perror("fork"); goto cleanup; }
    if (!child) {
        close(channel[0]);
        struct __user_cap_header_struct header = { _LINUX_CAPABILITY_VERSION_3, 0 };
        struct __user_cap_data_struct empty[2] = { {0}, {0} };
        struct child_result result = {0};
        errno = 0;
        if (syscall(SYS_capset, &header, empty)) result.capset_error = errno;
        errno = 0;
        ssize_t bytes = fgetxattr(fd, marker, actual, sizeof(actual));
        result.read_error = bytes == -1 ? errno : 0;
        result.marker_listed = listed(fd);
        result.identity_unchanged = !fstat(fd, &after) && before.st_dev == after.st_dev && before.st_ino == after.st_ino;
        ssize_t written = write(channel[1], &result, sizeof(result));
        close(channel[1]);
        _exit(written == (ssize_t) sizeof(result) ? 0 : 2);
    }
    close(channel[1]);
    struct child_result result;
    ssize_t received = read(channel[0], &result, sizeof(result));
    close(channel[0]);
    int child_status;
    if (waitpid(child, &child_status, 0) != child || !WIFEXITED(child_status) || WEXITSTATUS(child_status) ||
            received != (ssize_t) sizeof(result) || result.capset_error || result.read_error != ENODATA ||
            result.marker_listed != 0 || !result.identity_unchanged) {
        fprintf(stderr, "child-only capability-drop observation failed\n");
        goto cleanup;
    }
    if (fgetxattr(fd, marker, actual, sizeof(actual)) != (ssize_t) sizeof(actual) ||
            memcmp(actual, expected, sizeof(actual)) || listed(fd) != 1) {
        fprintf(stderr, "parent visibility or canary changed after child observation\n");
        goto cleanup;
    }
    printf("{\"mode\":\"privileged\",\"canaryBytes\":32,\"parentListedBefore\":1,\"parentListedAfter\":1,"
        "\"childGetErrno\":%d,\"childListed\":0,\"sameOpenedInode\":true,\"filesystemType\":%lu}\n",
        result.read_error, (unsigned long) filesystem.f_type);
    status = 0;
cleanup:
    /* Only delete our still-identical exclusively created leaf. Retain changed
     * paths for diagnosis instead of deleting another process's replacement. */
    if (fd >= 0 && parent >= 0) {
        if (!fstat(fd, &before) && !fstatat(parent, "canary", &after, AT_SYMLINK_NOFOLLOW) &&
                before.st_dev == after.st_dev && before.st_ino == after.st_ino) {
            if (unlinkat(parent, "canary", 0)) { perror("canary cleanup"); status = 1; }
        }
        else { fprintf(stderr, "canary path changed; retained\n"); status = 1; }
    }
    if (fd >= 0 && close(fd)) status = 1;
    if (parent >= 0 && close(parent)) status = 1;
    if (rmdir(directory)) { perror("owned directory cleanup"); status = 1; }
    return status;
}
