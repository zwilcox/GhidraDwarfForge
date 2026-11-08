#include <stdio.h>
#include <unistd.h>

static volatile unsigned int sink;

__attribute__((noinline)) void profile_hot(void)
{
    for (unsigned int index = 0; index < 600000000U; ++index) {
        sink ^= index;
    }
}

int main(void)
{
    /* The recording harness must never run even this owned target as root. */
    if (getuid() == 0 || geteuid() == 0) {
        return 2;
    }
    profile_hot();
    if (sink != 0) {
        return 3;
    }
    puts("FORGE_PERF_TARGET_PASS_UNPRIVILEGED");
    return 0;
}
