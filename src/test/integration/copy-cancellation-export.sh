#!/usr/bin/env bash
set -euo pipefail

# Linux compiler/Ghidra integration. Uses the installed production script and
# packaged native libraries; cancellation is triggered by actual copied bytes.
if [[ $# -ne 1 ]]; then
    echo "usage: $0 <installed-ghidra-dir>" >&2
    exit 64
fi
repository_dir=$(realpath "$(dirname "$0")/../../..")
ghidra_dir=$(realpath "$1")
result_root="$repository_dir/build/test-results/copy-cancellation-export"
mkdir -p "$result_root"
work=$(mktemp -d "$result_root/run.XXXXXXXX")
mkdir "$work/projects" "$work/output"
cleanup() {
    rm -f -- "$work/input.elf"
    rm -rf -- "$work/projects"
    echo "copy-cancellation-export results=$work"
}
trap cleanup EXIT
cat >"$work/fixture.c" <<'EOF'
__attribute__((noinline)) int add_one(int value)
{
    return value + 1;
}

int main(void)
{
    return add_one(41) == 42 ? 0 : 1;
}
EOF
cc -O0 -fno-pie -no-pie "$work/fixture.c" -o "$work/input.elf"
strip --strip-all "$work/input.elf"
truncate -s 134217728 "$work/input.elf"
sha256sum "$work/input.elf" >"$work/input.sha256"
printf 'previous sidecar\n' >"$work/output/previous.dbg"
printf 'previous source\n' >"$work/output/previous.dbg.c"
sha256sum "$work/output/previous.dbg" "$work/output/previous.dbg.c" \
    >"$work/prior-output.sha256"
"$ghidra_dir/support/analyzeHeadless" "$work/projects" CopyCancellation \
    -deleteProject -import "$work/input.elf" -loader ElfLoader \
    -analysisTimeoutPerFile 120 \
    -scriptPath "$repository_dir/src/test/integration/ghidra_scripts" \
    -postScript CancelDuringElfCopy.java "$work/input.elf" "$work/output/previous.dbg" \
    >"$work/export.log" 2>&1
grep -Fq 'production-copy-cancellation=PASS' "$work/export.log"
grep -Fq '"status":"CANCELLED"' "$work/export.log"
if grep -Eq '"status":"(SUCCESS|PARTIAL|FATAL)"|OutOfMemoryError|SIGSEGV|access violation' \
        "$work/export.log"; then
    echo "production copy cancellation had an unexpected result" >&2
    exit 1
fi
sha256sum -c "$work/input.sha256" >"$work/input-preservation.txt"
sha256sum -c "$work/prior-output.sha256" >"$work/output-preservation.txt"
test "$(find "$work/output" -maxdepth 1 -type f | wc -l)" = 2
{
    grep -F 'copy-cancelled-after-bytes=' "$work/export.log"
    echo 'report=CANCELLED'
    echo 'original-and-prior-pair-preserved=PASS'
    echo 'copy-cancellation-export=PASS'
} >"$work/result.txt"
cat "$work/result.txt"
