#!/usr/bin/env python3
"""Exercise bounded, complete frame diagnostics; no target execution is claimed."""

import argparse
from collections import Counter
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shlex
import subprocess
import sys
import tempfile


CAPACITY = 65536
CALLOC_MARKER = "FORGE_TEST_CALLOC_FAILURE"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, log, environment=None):
    command = [str(value) for value in command]
    log.with_name(log.name + ".command.json").write_text(json.dumps(command, indent=4) + "\n")
    result = subprocess.run(command, capture_output=True, text=True,
        env=environment, timeout=120)
    log.write_text(result.stdout)
    log.with_name(log.name + ".stderr").write_text(result.stderr)
    log.with_name(log.name + ".status").write_text(str(result.returncode) + "\n")
    return result


def clean_run(command, log):
    result = run(command, log)
    require(result.returncode == 0 and not result.stderr, "command failed: " + str(log))
    return result


def fixture(work, count):
    source = work / ("frames-" + str(count) + ".s")
    source.write_text(".text\n.globl _start\n_start:\n.rept " + str(count) +
        "\n.cfi_startproc\nnop\n.cfi_endproc\n.endr\n" +
        '.section .note.GNU-stack,"",@progbits\n')
    obj = source.with_suffix(".o")
    artifact = source.with_suffix(".dbg")
    original = source.with_suffix(".elf")
    clean_run(["as", "--gdwarf-5", "-o", obj, source], source.with_suffix(".as.txt"))
    clean_run(["ld", "-e", "_start", "-o", artifact, obj], source.with_suffix(".ld.txt"))
    clean_run(["objcopy", "--strip-debug", artifact, original], source.with_suffix(".strip.txt"))
    return original, artifact


SHIM = r'''#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Linux/glibc-only test hook avoids dlsym recursion inside calloc. */
extern void *__libc_calloc(size_t count, size_t size);

void *calloc(size_t count, size_t size)
{
    static unsigned matching = 0;
    const char *kind = getenv("FORGE_FAIL_CALLOC_KIND");
    const char *at = getenv("FORGE_FAIL_CALLOC_AT");
    int matches = kind && at &&
        ((!strcmp(kind, "array") && count == 65537 && size == sizeof(char *)) ||
        (!strcmp(kind, "string") && count == 1 && size == 300));
    if (matches && ++matching == strtoul(at, NULL, 10)) {
        const char marker[] = "FORGE_TEST_CALLOC_FAILURE\n";
        (void)write(2, marker, sizeof(marker) - 1);
        errno = ENOMEM;
        return NULL;
    }
    return __libc_calloc(count, size);
}
'''


API_CONTROL = r'''#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "libdwarf.h"

#define REQUIRE(value) do { if (!(value)) { \
    fprintf(stderr, "API assertion failed at line %d\n", __LINE__); return 2; \
} } while (0)

int main(int argc, char **argv)
{
    Dwarf_Debug dbg = NULL;
    Dwarf_Error error = NULL;
    const char *messages[4];
    unsigned count = 0;
    char message[32];
    int fd;
    REQUIRE(argc == 4);
    fd = open(argv[1], O_RDONLY);
    REQUIRE(fd >= 0);
    REQUIRE(dwarf_init_b(fd, DW_GROUPNUMBER_ANY, NULL, NULL, &dbg, &error) == DW_DLV_OK);
    dwarf_set_harmless_error_list_size(dbg, 3);
    REQUIRE(dwarf_set_harmless_error_list_size(dbg, 0) == 3);
    for (unsigned index = 0; index < 5; ++index) {
        snprintf(message, sizeof(message), "retained-%u", index);
        dwarf_insert_harmless_error(dbg, message);
    }
    REQUIRE(setenv("FORGE_FAIL_CALLOC_KIND", argv[2], 1) == 0);
    REQUIRE(setenv("FORGE_FAIL_CALLOC_AT", argv[3], 1) == 0);
    REQUIRE(dwarf_set_harmless_error_list_size(dbg, 65536) == 3);
    REQUIRE(dwarf_set_harmless_error_list_size(dbg, 0) == 3);
    REQUIRE(dwarf_get_harmless_error_list(dbg, 4, messages, &count) == DW_DLV_OK);
    REQUIRE(count == 5 && messages[0] && messages[1] && messages[2] && !messages[3]);
    REQUIRE(!strcmp(messages[0], "retained-2") && !strcmp(messages[1], "retained-3") &&
        !strcmp(messages[2], "retained-4"));
    REQUIRE(dwarf_finish(dbg) == DW_DLV_OK);
    REQUIRE(close(fd) == 0);
    puts("resize-failure-preserves-capacity-messages-count=PASS");
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tool", type=Path)
    parser.add_argument("--previous-tool", type=Path)
    parser.add_argument("--libdwarf-source", type=Path,
        help="configured patched source tree, for the static C API allocation-failure control")
    args = parser.parse_args()
    require(platform.system() == "Linux" and platform.machine() == "x86_64",
        "capacity regression requires Linux/glibc x86-64 assembler and preload controls")
    repository = Path(__file__).resolve().parents[3]
    tool = args.tool.resolve(strict=True)
    root = repository / "build/test-results/dwarfdump-diagnostic-capacity"
    root.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="run.", dir=root))
    print("dwarfdump-diagnostic-capacity-results=" + str(work), flush=True)
    helper = repository / "src/test/integration/check-dwarfdump.py"
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("strict_dwarfdump", helper)
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    clean_run([tool, "--version"], work / "version.txt")
    summary = {"tool_sha256": digest(tool), "capacity": CAPACITY,
        "positive_counts": [], "negative_controls": [], "hashes": {}}
    pairs = {}
    for count in (50, CAPACITY, CAPACITY + 1):
        original, artifact = fixture(work, count)
        pairs[count] = (original, artifact)
        for path in (original, artifact):
            summary["hashes"][str(path)] = digest(path)
        if count > CAPACITY:
            result = run([tool, "--no-follow-debuglink", "-ka", "-ki", "-kd", artifact],
                work / "over-capacity.txt")
            require(result.returncode == 1 and result.stderr.strip() ==
                "ERROR: harmless diagnostic count 65537 exceeds limit 65536 or retrieval failed",
                "over-capacity input did not fail normally and explicitly")
            summary["negative_controls"].append("over-capacity")
            continue
        log = work / ("complete-" + str(count) + ".txt")
        clean_run([sys.executable, helper, artifact, log, "--tool", tool,
            "--original", original], work / ("complete-" + str(count) + ".runner.txt"))
        metadata = json.loads(log.with_name(log.name + ".check.json").read_text())
        require(metadata["status"] == "PASS" and metadata["exit_status"] == 0 and
            metadata["reported_errors"] == count and metadata["uncorroborated_errors"] == 0,
            "incomplete or uncorroborated positive diagnostics")
        diagnostics = checker.frame_diagnostics(log.read_text())
        original_log = Path(metadata["original_check"]["log"])
        require(len(diagnostics) == count and len(set(diagnostics)) == count and
            Counter(diagnostics) == Counter(checker.frame_diagnostics(original_log.read_text())),
            "positive diagnostics do not preserve every distinct original message")
        require(metadata["original_check"]["exit_status"] == 0 and
            not Path(metadata["stderr_log"]).read_bytes() and
            not Path(metadata["original_check"]["stderr_log"]).read_bytes(),
            "positive checker did not complete cleanly")
        summary["positive_counts"].append(count)
        print("complete-diagnostics-" + str(count) + "=PASS", flush=True)

    raw = (work / "complete-50.txt").read_text()
    diagnostics = checker.frame_diagnostics(raw)
    for label, changed in (
            ("missing-message", raw.replace(diagnostics[0] + "\n", "", 1)),
            ("duplicated-message", raw.replace(diagnostics[0], diagnostics[1], 1))):
        require(changed != raw, "parser control did not change a diagnostic")
        (work / (label + ".txt")).write_text(changed)
        try:
            checker.validate_output(changed, diagnostics)
        except checker.ValidationFailure as failure:
            require(str(failure) == "uncorroborated inherited frame diagnostics",
                "wrong parser-control failure: " + str(failure))
        else:
            raise AssertionError("strict parser accepted " + label)
        summary["negative_controls"].append(label)

    shim_source = work / "fail-calloc.c"
    shim_source.write_text(SHIM)
    shim = work / "fail-calloc.so"
    clean_run(["gcc", "-shared", "-fPIC", "-Wall", "-Wextra", "-Werror", "-o", shim,
        shim_source], work / "shim-build.txt")
    for label, kind, at, diagnostic in (
            ("storage-array", "array", 1, "ERROR: cannot allocate harmless diagnostic capacity 65536"),
            ("storage-string", "string", 100, "ERROR: cannot allocate harmless diagnostic capacity 65536"),
            ("output-array", "array", 2, "ERROR: cannot allocate harmless diagnostic pointer buffer")):
        environment = dict(os.environ, LD_PRELOAD=str(shim),
            FORGE_FAIL_CALLOC_KIND=kind, FORGE_FAIL_CALLOC_AT=str(at))
        result = run([tool, "--no-follow-debuglink", "-ka", "-ki", "-kd", pairs[50][1]],
            work / (label + ".txt"), environment)
        require(result.returncode == 1 and result.stderr.splitlines() == [CALLOC_MARKER, diagnostic],
            "allocation failure was not a controlled normal exit: " + label)
        summary["negative_controls"].append(label)

    if args.libdwarf_source:
        lib = args.libdwarf_source.resolve(strict=True) / "src/lib/libdwarf"
        libraries = re.findall(r"^dependency_libs='([^']*)'$",
            (lib / "libdwarf.la").read_text(), re.MULTILINE)
        require(len(libraries) == 1, "missing configured static-library dependency metadata")
        dependencies = shlex.split(libraries[0])
        require(all(value in ("-lz", "-lzstd") for value in dependencies),
            "unexpected configured static-library dependency")
        api_source = work / "resize-failure.c"
        api_source.write_text(API_CONTROL)
        api = work / "resize-failure"
        clean_run(["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-I", lib,
            api_source, lib / ".libs/libdwarf.a", *dependencies, "-o", api], work / "api-build.txt")
        for kind, at in (("array", 1), ("string", 100)):
            environment = dict(os.environ, LD_PRELOAD=str(shim))
            environment.pop("FORGE_FAIL_CALLOC_KIND", None)
            environment.pop("FORGE_FAIL_CALLOC_AT", None)
            result = run([api, pairs[50][1], kind, at], work / ("resize-" + kind + ".txt"), environment)
            require(result.returncode == 0 and result.stderr.splitlines() == [CALLOC_MARKER] and
                result.stdout.strip() == "resize-failure-preserves-capacity-messages-count=PASS",
                "failed resize lost prior capacity/messages/counter: " + kind)
        summary["resize_failure_preservation"] = "PASS"
    else:
        summary["resize_failure_preservation"] = "NOT_RUN: supply --libdwarf-source"

    if args.previous_tool:
        result = run([args.previous_tool.resolve(strict=True), "--no-follow-debuglink",
            "-ka", "-ki", "-kd", pairs[50][1]], work / "previous-capacity.txt")
        require(result.returncode == 0 and not result.stderr and
            re.findall(r"HARMLESS ERROR COUNT:\s*(\d+)", result.stdout) == ["50"] and
            len(checker.frame_diagnostics(result.stdout)) == 49,
            "previous tool did not reproduce the retained/reported mismatch")
        summary["previous_capacity_reproduced"] = True

    for name, before in summary["hashes"].items():
        require(digest(Path(name)) == before, "input changed: " + name)
    (work / "summary.json").write_text(json.dumps(summary, indent=4) + "\n")
    (work / "result.txt").write_text("dwarfdump-diagnostic-capacity=PASS\n")
    print("dwarfdump-diagnostic-capacity=PASS")


if __name__ == "__main__":
    main()
