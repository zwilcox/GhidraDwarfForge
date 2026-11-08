/* Linux validator process owner. No code from this file runs inside the JVM.
 * Protocol and API audit: docs/VALIDATOR-SUPERVISION.md.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CLEANUP_MS 5000
#define MAX_TIMEOUT_MS 3600000
#define MAX_OUTPUT_BYTES (256ULL * 1024 * 1024)

static volatile sig_atomic_t interrupted;
static void interrupt_handler(int signal_number) { (void)signal_number; interrupted = 1; }

static int64_t millis(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static bool number(const char *text, uint64_t maximum, uint64_t *value) {
    if (!*text) return false;
    *value = 0;
    for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
        if (*p < '0' || *p > '9' || *value > (maximum - (*p - '0')) / 10) return false;
        *value = *value * 10 + (*p - '0');
    }
    return *value > 0 && *value <= maximum;
}

static int exclusive(const char *path) {
    return open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
}

static bool write_all(int fd, const void *buffer, size_t length) {
    const char *cursor = buffer;
    while (length) {
        ssize_t written = write(fd, cursor, length);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return false;
        cursor += written;
        length -= (size_t)written;
    }
    return true;
}

/* Every PID read here is our own direct, unreaped child. This single-threaded
 * process does not wait/reap during enumeration/signalling, so even a child
 * exiting between read and kill cannot have its PID reused. No late process-
 * group identifier or descendant snapshot is used as signal authority.
 * Killing parents causes their orphan children to be adopted by this subreaper;
 * repeat until waitpid explicitly establishes ECHILD.
 */
static bool kill_children(void) {
    char path[96];
    snprintf(path, sizeof(path), "/proc/self/task/%ld/children", (long)getpid());
    FILE *input = fopen(path, "re");
    if (!input) return false;
    bool success = true;
    long pid;
    int scanned;
    while ((scanned = fscanf(input, "%ld", &pid)) == 1) {
        if (pid <= 0 || pid > INT_MAX) { success = false; break; }
        if (kill((pid_t)pid, SIGKILL) != 0 && errno != ESRCH) success = false;
    }
    if (scanned != EOF || ferror(input)) success = false;
    if (fclose(input) != 0) success = false;
    return success;
}

typedef struct {
    int pipe;
    int log;
    uint64_t observed;
    uint64_t retained;
    bool eof;
} stream;

static bool drain(stream *output, uint64_t cap, bool *exceeded) {
    if (output->eof) return true;
    char bytes[16384];
    ssize_t count = read(output->pipe, bytes, sizeof(bytes));
    if (count == 0) {
        output->eof = true;
        close(output->pipe);
        output->pipe = -1;
        return true;
    }
    if (count < 0) return errno == EAGAIN || errno == EINTR;
    output->observed += (uint64_t)count;
    size_t keep = (size_t)((uint64_t)count < cap - output->retained ? (uint64_t)count : cap - output->retained);
    if (!write_all(output->log, bytes, keep)) return false;
    output->retained += keep;
    if (output->observed > cap) *exceeded = true;
    return true;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        puts("forge-validator-supervisor 1 linux-subreaper");
        return 0;
    }
    uint64_t timeout, cap;
    if (argc < 8 || !number(argv[1], MAX_TIMEOUT_MS, &timeout) ||
            !number(argv[2], MAX_OUTPUT_BYTES, &cap) || strcmp(argv[6], "--") != 0 || argv[7][0] != '/') {
        fputs("usage: supervisor timeout-ms stream-byte-cap status-new stdout-new stderr-new -- /absolute/tool [args...]\n", stderr);
        return 64;
    }
    /* Never inherit automatic child reaping; numeric child identity safety
     * depends on retaining zombies until our own waitpid call. */
    struct sigaction reset = { .sa_handler = SIG_DFL };
    struct sigaction stop = { .sa_handler = interrupt_handler };
    sigemptyset(&reset.sa_mask);
    sigemptyset(&stop.sa_mask);
    if (sigaction(SIGCHLD, &reset, NULL) != 0 || sigaction(SIGTERM, &stop, NULL) != 0 ||
            sigaction(SIGINT, &stop, NULL) != 0 || prctl(PR_SET_CHILD_SUBREAPER, 1L) != 0) {
        perror("supervisor setup"); return 70;
    }
    struct stat control_stat;
    if (fstat(STDIN_FILENO, &control_stat) != 0 || !S_ISFIFO(control_stat.st_mode) || !kill_children()) {
        fputs("supervisor requires a cancellation pipe and readable child accounting\n", stderr);
        return 70;
    }
    int status_file = exclusive(argv[3]);
    if (status_file < 0) { perror("exclusive supervisor status"); return 70; }
    int logs[2] = { exclusive(argv[4]), -1 };
    if (logs[0] >= 0) logs[1] = exclusive(argv[5]);
    int pipes[2][2] = { {-1, -1}, {-1, -1} };
    if (logs[0] < 0 || logs[1] < 0 || pipe2(pipes[0], O_CLOEXEC) != 0 || pipe2(pipes[1], O_CLOEXEC) != 0) {
        perror("exclusive supervisor logs/pipes"); return 70;
    }
    int64_t started = millis();
    if (started < 0 || fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK) < 0 ||
            fcntl(pipes[0][0], F_SETFL, O_NONBLOCK) < 0 || fcntl(pipes[1][0], F_SETFL, O_NONBLOCK) < 0) {
        perror("supervisor clock/pipe flags"); return 70;
    }
    pid_t child = fork();
    if (child == 0) {
        struct rlimit core_limit = { 0, 0 };
        int input = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (input < 0 || dup2(input, STDIN_FILENO) < 0 || dup2(pipes[0][1], STDOUT_FILENO) < 0 ||
                dup2(pipes[1][1], STDERR_FILENO) < 0 || close_range(3, UINT_MAX, 0) != 0 ||
                setrlimit(RLIMIT_CORE, &core_limit) != 0) _exit(126);
        sigaction(SIGTERM, &reset, NULL);
        sigaction(SIGINT, &reset, NULL);
        sigaction(SIGPIPE, &reset, NULL);
        execv(argv[7], argv + 7);
        _exit(127);
    }
    if (child < 0) { perror("supervisor fork"); return 70; }
    close(pipes[0][1]);
    close(pipes[1][1]);
    stream outputs[2] = {{pipes[0][0], logs[0], 0, 0, false}, {pipes[1][0], logs[1], 0, 0, false}};
    const char *reason = NULL;
    bool root_done = false, all_gone = false, cleanup_ok = true, exceeded = false;
    int root_status = 0;
    int64_t cleanup_started = 0;
    for (;;) {
        if (reason && !all_gone && !kill_children()) cleanup_ok = false;
        int observed_status;
        pid_t observed;
        while ((observed = waitpid(-1, &observed_status, WNOHANG)) > 0) {
            if (observed == child) { root_done = true; root_status = observed_status; }
        }
        if (observed < 0 && errno == ECHILD) all_gone = true;
        else if (observed < 0 && errno != EINTR) { reason = "internal_error"; cleanup_ok = false; }
        for (size_t i = 0; i < 2; i++) {
            if (!drain(&outputs[i], cap, &exceeded)) { reason = "internal_error"; cleanup_ok = false; }
        }
        int64_t now = millis();
        if (now < 0) { reason = "internal_error"; cleanup_ok = false; }
        if (!reason) {
            if (exceeded) reason = "output_limit";
            else if (interrupted) reason = "cancelled";
            else if (root_done && !all_gone) reason = "descendants";
            else if (now - started >= (int64_t)timeout) reason = "timeout";
        }
        if (all_gone && outputs[0].eof && outputs[1].eof) break;
        if (reason && !cleanup_started) cleanup_started = now;
        if (reason && (now < 0 || now - cleanup_started >= CLEANUP_MS)) { cleanup_ok = false; break; }
        struct pollfd ready[3] = {
            { reason ? -1 : STDIN_FILENO, POLLIN | POLLHUP, 0 },
            { outputs[0].pipe, POLLIN | POLLHUP, 0 },
            { outputs[1].pipe, POLLIN | POLLHUP, 0 }
        };
        int polled = poll(ready, 3, 10);
        if (polled < 0 && errno != EINTR) { reason = "internal_error"; cleanup_ok = false; }
        if (!reason && (ready[0].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL))) reason = "cancelled";
    }
    bool complete = cleanup_ok && all_gone && root_done && outputs[0].eof && outputs[1].eof;
    int exit_code = root_done && WIFEXITED(root_status) ? WEXITSTATUS(root_status) : -1;
    int exit_signal = root_done && WIFSIGNALED(root_status) ? WTERMSIG(root_status) : 0;
    if (!reason) reason = exit_code == 0 && complete ? "completed" : "tool_error";
    for (size_t i = 0; i < 2; i++) {
        if (outputs[i].pipe >= 0) close(outputs[i].pipe);
        if (fsync(outputs[i].log) != 0) complete = false;
        if (close(outputs[i].log) != 0) complete = false;
    }
    char record[1024];
    int length = snprintf(record, sizeof(record),
        "{\"schemaVersion\":1,\"reason\":\"%s\",\"exitCode\":%d,\"exitSignal\":%d,"
        "\"cleanupComplete\":%s,\"stdoutObserved\":%llu,\"stdoutRetained\":%llu,"
        "\"stderrObserved\":%llu,\"stderrRetained\":%llu}\n", reason, exit_code, exit_signal,
        complete ? "true" : "false", (unsigned long long)outputs[0].observed,
        (unsigned long long)outputs[0].retained, (unsigned long long)outputs[1].observed,
        (unsigned long long)outputs[1].retained);
    bool recorded = length > 0 && (size_t)length < sizeof(record) && write_all(status_file, record, (size_t)length);
    if (fsync(status_file) != 0 || close(status_file) != 0) recorded = false;
    return recorded && complete && exit_code == 0 && strcmp(reason, "completed") == 0 ? 0 : 20;
}
