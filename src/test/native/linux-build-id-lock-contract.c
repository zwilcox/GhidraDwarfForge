#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

/* Audit the Linux Intel LP64 libc ABI before invoking it from isolated Java. */
_Static_assert(sizeof(void *) == 8 && sizeof(long) == 8, "LP64 required");
_Static_assert(sizeof(struct flock) == 32, "flock size");
_Static_assert(offsetof(struct flock, l_type) == 0 && sizeof(((struct flock *)0)->l_type) == 2, "type");
_Static_assert(offsetof(struct flock, l_whence) == 2 && sizeof(((struct flock *)0)->l_whence) == 2, "whence");
_Static_assert(offsetof(struct flock, l_start) == 8 && sizeof(((struct flock *)0)->l_start) == 8, "start");
_Static_assert(offsetof(struct flock, l_len) == 16 && sizeof(((struct flock *)0)->l_len) == 8, "length");
_Static_assert(offsetof(struct flock, l_pid) == 24 && sizeof(((struct flock *)0)->l_pid) == 4, "pid");
_Static_assert(F_OFD_SETLK == 37 && F_WRLCK == 1 && SEEK_SET == 0, "lock constants");
_Static_assert(O_RDWR == 2 && O_NOFOLLOW == 0x20000 && O_CLOEXEC == 0x80000, "open flags");
_Static_assert(EACCES == 13 && EAGAIN == 11, "busy errno");

int main(void)
{
    int (*open_signature)(const char *, int, ...) = open;
    int (*fcntl_signature)(int, int, ...) = fcntl;
    int (*close_signature)(int) = close;
    if (!open_signature || !fcntl_signature || !close_signature) {
        return 1;
    }
    puts("linux-build-id-lock-contract=PASS LP64 flock=32 type=0 whence=2 start=8 length=16 pid=24");
    return 0;
}
