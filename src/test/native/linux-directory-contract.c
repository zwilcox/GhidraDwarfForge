#define _GNU_SOURCE
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <unistd.h>

/* Audited Linux Intel LP64 ABI; no libdwarf declarations. */
_Static_assert(sizeof(int) == 4 && sizeof(long) == 8, "LP64 ABI");
_Static_assert(sizeof(struct statx) == 256, "statx extent");
_Static_assert(offsetof(struct statx, stx_mode) == 28, "mode offset");
_Static_assert(offsetof(struct statx, stx_ino) == 32, "inode offset");
_Static_assert(offsetof(struct statx, stx_dev_major) == 136, "device offset");
_Static_assert(offsetof(struct statx, stx_dev_minor) == 140, "device minor offset");
_Static_assert(offsetof(struct statx, stx_mnt_id) == 144, "mount offset");
_Static_assert(sizeof(struct statfs) == 120, "statfs extent");
_Static_assert(offsetof(struct statfs, f_type) == 0, "type offset");
_Static_assert(offsetof(struct statfs, f_fsid) == 56 && sizeof(((struct statfs *) 0)->f_fsid) == 8, "fsid extent/offset");
_Static_assert(offsetof(struct statfs, f_namelen) == 64, "name bound offset");
_Static_assert(offsetof(struct statfs, f_flags) == 80, "mount flags offset");
_Static_assert(O_DIRECTORY == 0x10000 && O_NOFOLLOW == 0x20000 &&
    O_CLOEXEC == 0x80000 && O_NONBLOCK == 0x800 && O_RDONLY == 0, "open flags");
_Static_assert(AT_FDCWD == -100 && AT_EMPTY_PATH == 0x1000 && AT_SYMLINK_NOFOLLOW == 0x100, "statx flags");
_Static_assert((STATX_TYPE | STATX_INO | STATX_MNT_ID) == 0x1101, "statx mask");

int main(int argc, char **argv) {
    int (*open_call)(const char *, int, ...) = open;
    int (*stat_call)(int, const char *, int, unsigned int, struct statx *) = statx;
    int (*fs_call)(int, struct statfs *) = fstatfs;
    int (*sync_call)(int) = fsync;
    int (*close_call)(int) = close;
    if (!open_call || !stat_call || !fs_call || !sync_call || !close_call) return 1;
    if (argc == 1) {
        puts("linux-directory-contract=PASS LP64 statfs=120 statx=256");
        return 0;
    }
    if (argc != 2) return 2;
    int fd = open(argv[1], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) { perror("open"); return 3; }
    struct stat s;
    struct statx sx;
    struct statfs fs;
    if (fstat(fd, &s) || fstatfs(fd, &fs) ||
            statx(fd, "", AT_EMPTY_PATH, STATX_MNT_ID, &sx)) {
        perror("stat"); close(fd); return 4;
    }
    if (!(sx.stx_mask & STATX_MNT_ID)) { close(fd); return 5; }
    printf("{\"identity\":\"%u:%u:%llu@%llu\",\"fileSystemType\":%ld,\"fileSystemId\":\"",
        major(s.st_dev), minor(s.st_dev), (unsigned long long) s.st_ino,
        (unsigned long long) sx.stx_mnt_id, (long) fs.f_type);
    const unsigned char *id = (const unsigned char *) &fs.f_fsid;
    for (size_t i = 0; i < sizeof(fs.f_fsid); i++) printf("%02x", id[i]);
    printf("\",\"mountFlags\":%ld,\"maximumNameBytes\":%ld}\n", (long) fs.f_flags, (long) fs.f_namelen);
    if (close(fd)) { perror("close"); return 6; }
    return 0;
}
