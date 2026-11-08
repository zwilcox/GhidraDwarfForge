/* Linux-only test preload: permit attaching to this owned child and optionally
 * exec a different image after the original program completes. Target files
 * and their code are not patched. */
#include <signal.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <unistd.h>

static void replace_image(void) {
    const char *next = getenv("FORGE_LOADER_EXEC");
    if (next != NULL) {
        unsetenv("LD_PRELOAD");
        execl(next, next, (char *)NULL);
        _exit(125);
    }
}

__attribute__((constructor))
static void prepare_lifecycle(void) {
    if (prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0) != 0) {
        _exit(126);
    }
    if (atexit(replace_image) != 0) {
        _exit(127);
    }
    if (write(STDOUT_FILENO, "FORGE_ATTACH_READY\n", 19) != 19) {
        _exit(124);
    }
    raise(SIGSTOP);
}
