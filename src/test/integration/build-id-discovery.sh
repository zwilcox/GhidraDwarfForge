#!/usr/bin/env bash
set -euo pipefail

repository_dir=$(realpath "$(dirname "$0")/../../..")
fixture_dir="$repository_dir/build/fixtures/x86_64"
input="$fixture_dir/semantic.exec.stripped"
sidecar="$fixture_dir/semantic.exec.ghidra-forge.dbg"
mismatch="$fixture_dir/semantic.pie.ghidra-forge.dbg"
no_id_input="$fixture_dir/semantic.exec.no-build-id.stripped"
no_id_sidecar="$fixture_dir/semantic.exec.no-build-id.ghidra-forge.dbg"
result_dir="$repository_dir/build/test-results/build-id-discovery"
temporary_debug_root=$(mktemp -d -t ghidra-dwarf-forge-build-id.XXXXXXXX)

cleanup() {
    case "$temporary_debug_root" in
        /tmp/ghidra-dwarf-forge-build-id.*)
            rm -rf -- "$temporary_debug_root"
            ;;
        *)
            echo "refusing to remove unexpected temporary path: $temporary_debug_root" >&2
            ;;
    esac
}
trap cleanup EXIT

mkdir -p "$result_dir"
for required in "$input" "$sidecar" "$mismatch" "$no_id_input" "$no_id_sidecar"; do
    test -s "$required"
done
before=$(sha256sum "$input" | cut -d' ' -f1)
no_id_before=$(sha256sum "$no_id_input" | cut -d' ' -f1)
build_id=$(readelf -n "$input" | sed -n 's/.*Build ID: //p' | head -1)
sidecar_id=$(readelf -n "$sidecar" | sed -n 's/.*Build ID: //p' | head -1)
mismatch_id=$(readelf -n "$mismatch" | sed -n 's/.*Build ID: //p' | head -1)
test -n "$build_id"
test "$build_id" = "$sidecar_id"
test "$build_id" != "$mismatch_id"

debug_directory="$temporary_debug_root/.build-id/${build_id:0:2}"
debug_file="$debug_directory/${build_id:2}.debug"
mkdir -p "$debug_directory"
cp "$mismatch" "$debug_file"
mismatch_transcript="$result_dir/mismatched-build-id.txt"
gdb-multiarch -q -nx -batch \
    -ex "set debuginfod enabled off" \
    -ex "set debug-file-directory $temporary_debug_root" \
    -ex "file $input" \
    -ex "info functions recovered_add" >"$mismatch_transcript" 2>&1
grep -q 'has a different build-id, file skipped' "$mismatch_transcript"
if grep -q 'semantic[.]exec[.]ghidra-forge[.]dbg[.]c' "$mismatch_transcript"; then
    echo "GDB accepted a mismatched build-ID sidecar" >&2
    exit 1
fi

cp "$sidecar" "$debug_file"
transcript="$result_dir/matched-build-id.txt"
gdb-multiarch -q -nx -batch \
    -ex "set debuginfod enabled off" \
    -ex "set auto-solib-add off" \
    -ex "set debug-file-directory $temporary_debug_root" \
    -ex "directory $fixture_dir" \
    -ex "file $input" \
    -ex "info functions recovered_add" \
    -ex "ptype recovered_add" \
    -ex "list recovered_add" \
    -ex "break recovered_add" \
    -ex run \
    -ex "info args" >"$transcript" 2>&1

grep -q 'semantic[.]exec[.]ghidra-forge[.]dbg[.]c' "$transcript"
grep -Fq 'type = int (int, int)' "$transcript"
grep -q 'Breakpoint 1, recovered_add (left=19, right=23)' "$transcript"
grep -Fxq 'left = 19' "$transcript"
grep -Fxq 'right = 23' "$transcript"

if readelf -n "$no_id_input" | grep -q 'Build ID:' ||
        readelf -n "$no_id_sidecar" | grep -q 'Build ID:'; then
    echo "no-build-ID fixture or sidecar unexpectedly carries a build ID" >&2
    exit 1
fi
no_id_transcript="$result_dir/no-build-id-explicit.txt"
gdb-multiarch -q -nx -batch \
    -ex "set debuginfod enabled off" \
    -ex "set auto-solib-add off" \
    -ex "directory $fixture_dir" \
    -ex "file $no_id_input" \
    -ex "symbol-file $no_id_sidecar" \
    -ex "ptype recovered_add" \
    -ex "break recovered_add" \
    -ex run \
    -ex "info args" >"$no_id_transcript" 2>&1
grep -Fq 'type = int (int, int)' "$no_id_transcript"
grep -q 'Breakpoint 1, recovered_add (left=19, right=23)' "$no_id_transcript"
grep -Fxq 'left = 19' "$no_id_transcript"
grep -Fxq 'right = 23' "$no_id_transcript"
after=$(sha256sum "$input" | cut -d' ' -f1)
no_id_after=$(sha256sum "$no_id_input" | cut -d' ' -f1)
test "$before" = "$after"
test "$no_id_before" = "$no_id_after"

{
    echo "input_sha256=$after"
    echo "build_id=$build_id"
    echo "mismatched_build_id=$mismatch_id"
    echo "no_build_id_input_sha256=$no_id_after"
    echo "no_build_id_explicit_loading=PASS"
    echo "build_id_discovery=PASS"
} | tee "$result_dir/result.txt"
