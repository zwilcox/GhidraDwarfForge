#define _GNU_SOURCE
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#if !defined(__x86_64__)
#error This native host contract is currently validated only for Linux Intel LP64.
#endif

/* Audited Linux LP64 libc calls, unrelated to the libdwarf producer ABI. */
_Static_assert(sizeof(int) == 4 && sizeof(unsigned int) == 4, "32-bit scalar ABI");
_Static_assert(sizeof(size_t) == 8 && sizeof(ssize_t) == 8, "LP64 size ABI");
_Static_assert(sizeof(uid_t) == 4 && sizeof(gid_t) == 4 && sizeof(mode_t) == 4, "owner/mode ABI");
_Static_assert(sizeof(struct statx) == 256, "statx extent");
#define OFFSET(member, expected) _Static_assert(offsetof(struct statx, member) == expected, #member)
OFFSET(stx_mask, 0);
OFFSET(stx_attributes, 8);
OFFSET(stx_nlink, 16);
OFFSET(stx_uid, 20);
OFFSET(stx_gid, 24);
OFFSET(stx_mode, 28);
OFFSET(stx_ino, 32);
OFFSET(stx_size, 40);
OFFSET(stx_attributes_mask, 56);
OFFSET(stx_ctime, 96);
OFFSET(stx_mtime, 112);
OFFSET(stx_dev_major, 136);
OFFSET(stx_dev_minor, 140);
_Static_assert(sizeof(struct statx_timestamp) == 16, "statx time extent");
_Static_assert(offsetof(struct statx_timestamp, tv_nsec) == 8, "statx nanoseconds");
_Static_assert(sizeof(struct timespec) == 16 && sizeof(time_t) == 8, "LP64 timespec");
_Static_assert(offsetof(struct timespec, tv_nsec) == 8, "timespec nanoseconds");
_Static_assert(AT_FDCWD == -100 && AT_EMPTY_PATH == 0x1000 && AT_SYMLINK_NOFOLLOW == 0x100, "statx flags");
_Static_assert(O_RDONLY == 0 && O_RDWR == 2 && O_NONBLOCK == 0x800 &&
    O_CLOEXEC == 0x80000 && O_NOFOLLOW == 0x20000, "open flags");
_Static_assert(STATX_BASIC_STATS == 0x7ff && UTIME_OMIT == 0x3ffffffe, "metadata constants");

int main(void) {
    int (*stat_call)(int, const char *, int, unsigned int, struct statx *) = statx;
    ssize_t (*list_call)(int, char *, size_t) = flistxattr;
    ssize_t (*get_call)(int, const char *, void *, size_t) = fgetxattr;
    int (*set_call)(int, const char *, const void *, size_t, int) = fsetxattr;
    int (*remove_call)(int, const char *) = fremovexattr;
    int (*owner_call)(int, uid_t, gid_t) = fchown;
    int (*mode_call)(int, mode_t) = fchmod;
    int (*time_call)(int, const struct timespec *) = futimens;
    int (*open_call)(const char *, int, ...) = open;
    int (*close_call)(int) = close;
    if (!stat_call || !list_call || !get_call || !set_call || !remove_call ||
            !owner_call || !mode_call || !time_call || !open_call || !close_call) return 1;
    puts("linux-metadata-contract=PASS LP64 statx=256 timespec=16");
    return 0;
}
