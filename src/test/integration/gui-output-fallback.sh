#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
    echo "usage: $0 <ghidra-dir> <extension-module-dir> <fixture.stripped> <fixture.reference>" >&2
    echo "requires: Xvfb (or XVFB_BIN), GUI-enabled Java 21+ (or JAVA_BIN), javac," >&2
    echo "          readelf, llvm-dwarfdump, dwarfdump, gdb" >&2
    exit 2
fi

repository_dir=$(realpath "$(dirname "$0")/../../..")
ghidra_dir=$(realpath "$1")
module_dir=$(realpath "$2")
fixture=$(realpath "$3")
reference=$(realpath "$4")
xvfb_bin=${XVFB_BIN:-Xvfb}
java_bin=${JAVA_BIN:-java}
command -v "$xvfb_bin" >/dev/null
for dependency in "$java_bin" javac readelf llvm-dwarfdump dwarfdump gdb timeout; do
    command -v "$dependency" >/dev/null
done
if [[ $(id -u) == 0 ]]; then
    echo "the real unwritable-directory check requires a non-root user" >&2
    exit 2
fi

result_root="$repository_dir/build/test-results/gui-output-fallback"
mkdir -p "$result_root"
result_dir=$(mktemp -d "$result_root/run.XXXXXXXX")
mkdir -p "$result_dir/classes" "$result_dir/settings" "$result_dir/cache" \
    "$result_dir/tmp" "$result_dir/user"

cleanup() {
    if [[ -n ${xvfb_pid:-} ]]; then
        kill "$xvfb_pid" 2>/dev/null || true
        wait "$xvfb_pid" 2>/dev/null || true
    fi
    for original_dir in "$result_dir/select/readonly" "$result_dir/cancel/readonly"; do
        if [[ -d "$original_dir" ]]; then
            chmod u+w "$original_dir"
        fi
    done
}
trap cleanup EXIT

classpath="$module_dir/lib/GhidraDwarfForge.jar"
while IFS= read -r -d '' jar; do
    classpath+=":$jar"
done < <(find "$ghidra_dir/Ghidra" -path '*/Extensions' -prune -o \
    -type f -name '*.jar' -print0)
javac --release 21 -cp "$classpath" -d "$result_dir/classes" \
    "$module_dir/ghidra_scripts/GhidraDwarfForge.java" \
    "$repository_dir/src/test/integration/gui/GuiOutputFallbackSmoke.java"

"$xvfb_bin" -displayfd 3 -screen 0 1280x1024x24 -nolisten tcp \
    3>"$result_dir/display.txt" >"$result_dir/xvfb.log" 2>&1 &
xvfb_pid=$!
for attempt in {1..100}; do
    if [[ -s "$result_dir/display.txt" ]]; then
        break
    fi
    if ! kill -0 "$xvfb_pid" 2>/dev/null; then
        cat "$result_dir/xvfb.log" >&2
        exit 1
    fi
    sleep 0.1
done
test -s "$result_dir/display.txt"
display_number=$(<"$result_dir/display.txt")
consumer="$module_dir/os/linux_x86_64/libdwarf.so.2.3.2"
producer="$module_dir/os/linux_x86_64/libdwarfp.so.2.3.2"
function_address=$(readelf -Ws "$reference" | awk \
    '$8 == "recovered_add" { print $2; exit }')
test -n "$function_address"

DISPLAY=":$display_number" timeout 240 "$java_bin" --enable-native-access=ALL-UNNAMED \
    -Djava.awt.headless=false -Duser.home="$result_dir/user" \
    -Dapplication.settingsdir="$result_dir/settings" \
    -Dapplication.cachedir="$result_dir/cache" \
    -Dapplication.tempdir="$result_dir/tmp" -Djava.io.tmpdir="$result_dir/tmp" \
    -cp "$result_dir/classes:$classpath" GuiOutputFallbackSmoke \
    "$ghidra_dir" "$module_dir" "$fixture" "$consumer" "$producer" \
    "$result_dir" "$function_address" 2>&1 | tee "$result_dir/gui.log"

input="$result_dir/select/readonly/fixture"
sidecar="$result_dir/select/chosen/fixture.dbg"
readelf -h -S -n "$input" >"$result_dir/original-elf.txt" 2>"$result_dir/readelf-errors.txt"
readelf -h -S -n "$sidecar" >"$result_dir/sidecar-elf.txt" 2>>"$result_dir/readelf-errors.txt"
readelf --debug-dump=info --debug-dump=abbrev --debug-dump=aranges \
    --debug-dump=decodedline "$sidecar" >"$result_dir/readelf-dwarf.txt" \
    2>>"$result_dir/readelf-errors.txt"
test ! -s "$result_dir/readelf-errors.txt"
llvm-dwarfdump --verify "$sidecar" | tee "$result_dir/llvm-verify.txt"
python3 "$repository_dir/src/test/integration/check-dwarfdump.py" \
    "$sidecar" "$result_dir/dwarfdump.txt" --original "$input"
gdb -q -nx -batch \
    -ex 'set pagination off' -ex 'set confirm off' -ex 'set debuginfod enabled off' \
    -ex "file $input" -ex "directory $result_dir/select/chosen" \
    -ex 'set auto-solib-add off' -ex "symbol-file $sidecar" \
    -ex 'info functions gui_recovered_add' -ex 'list gui_recovered_add' \
    -ex 'break gui_recovered_add' -ex run \
    -ex 'python assert gdb.selected_frame().name() == "gui_recovered_add"' \
    -ex 'python import os; assert os.path.isfile(gdb.selected_frame().find_sal().symtab.fullname())' \
    -ex 'python before_next = int(gdb.parse_and_eval("$pc"))' -ex next \
    -ex 'python assert int(gdb.parse_and_eval("$pc")) != before_next' \
    -ex 'python before_step = int(gdb.parse_and_eval("$pc"))' -ex step \
    -ex 'python assert int(gdb.parse_and_eval("$pc")) != before_step' \
    -ex 'echo GUI_GDB_PASS\n' >"$result_dir/gdb.txt" 2>&1
grep -q 'Breakpoint 1, gui_recovered_add' "$result_dir/gdb.txt"
grep -q 'fixture.dbg.c:' "$result_dir/gdb.txt"
grep -q 'GUI_GDB_PASS' "$result_dir/gdb.txt"
if grep -Eq 'warning:|No such file|Error|Traceback|AssertionError' "$result_dir/gdb.txt"; then
    cat "$result_dir/gdb.txt" >&2
    exit 1
fi
grep -q 'GUI output fallback selection and cancellation PASS' "$result_dir/gui.log"
echo "GUI output fallback validation PASS: $result_dir"
