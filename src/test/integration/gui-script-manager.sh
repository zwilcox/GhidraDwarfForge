#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
    echo "usage: $0 <ghidra-dir> <installed-extension-module> <fixture.stripped> <fixture.reference>" >&2
    echo "requires Linux, Xvfb (or XVFB_BIN), GUI Java 21+ (or JAVA_BIN), javac, GNU/LLVM/libdwarf and GDB" >&2
    exit 64
fi
repository=$(realpath "$(dirname "$0")/../../..")
ghidra=$(realpath "$1")
module=$(realpath "$2")
fixture=$(realpath "$3")
reference=$(realpath "$4")
xvfb=${XVFB_BIN:-Xvfb}
java=${JAVA_BIN:-java}
for dependency in "$xvfb" "$java" javac readelf llvm-dwarfdump dwarfdump gdb timeout; do
    command -v "$dependency" >/dev/null
done
test -s "$module/ghidra_scripts/GhidraDwarfForge.java"
test -s "$module/ghidra_scripts/ExportGhidraDwarfForge.java"
(cd "$module" && sha256sum -c RELEASE-SHA256SUMS) >/dev/null
root="$repository/build/test-results/gui-script-manager"
mkdir -p "$root"
work=$(mktemp -d "$root/run.XXXXXXXX")
mkdir -p "$work/classes" "$work/settings" "$work/cache" "$work/tmp" "$work/user"
echo "gui-script-manager-results=$work"
cleanup() {
    if [[ -n ${xvfb_pid:-} ]]; then
        kill "$xvfb_pid" 2>/dev/null || true
        wait "$xvfb_pid" 2>/dev/null || true
    fi
    for restricted in "$work/select/readonly" "$work/cancel/readonly"; do
        if [[ -d "$restricted" ]]; then
            chmod u+w "$restricted"
        fi
    done
}
trap cleanup EXIT
classpath="$module/lib/GhidraDwarfForge.jar"
while IFS= read -r -d '' jar; do
    classpath+=":$jar"
done < <(find -L "$ghidra/Ghidra" \( -path '*/Extensions' -o -path '*/data' \) -prune \
    -o -type f -name '*.jar' -print0)
javac --release 21 -cp "$classpath" -d "$work/classes" \
    "$repository/src/test/integration/gui/GuiTestSupport.java" \
    "$repository/src/test/integration/gui/GuiScriptManagerSmoke.java"
"$xvfb" -displayfd 3 -screen 0 1280x1024x24 -nolisten tcp \
    3>"$work/display.txt" >"$work/xvfb.log" 2>&1 &
xvfb_pid=$!
for attempt in {1..100}; do
    if [[ -s "$work/display.txt" ]]; then
        break
    fi
    kill -0 "$xvfb_pid"
    sleep 0.1
done
test -s "$work/display.txt"
display=$(<"$work/display.txt")
function_address=$(readelf -Ws "$reference" | awk '$8 == "recovered_add" && !found++ { print $2 }')
test -n "$function_address"
DISPLAY=":$display" timeout 300 "$java" --enable-native-access=ALL-UNNAMED \
    -Djava.awt.headless=false -Duser.home="$work/user" \
    -Dapplication.settingsdir="$work/settings" -Dapplication.cachedir="$work/cache" \
    -Dapplication.tempdir="$work/tmp" -Djava.io.tmpdir="$work/tmp" \
    -cp "$work/classes:$classpath" GuiScriptManagerSmoke \
    "$ghidra" "$module" "$fixture" "$work" "$function_address" \
    2>&1 | tee "$work/gui.log"
input="$work/select/readonly/fixture"
sidecar="$work/select/chosen/fixture.dbg"
readelf -h -S -n "$input" > "$work/input-elf.txt" 2> "$work/readelf.stderr"
readelf -h -S -n "$sidecar" > "$work/sidecar-elf.txt" 2>> "$work/readelf.stderr"
readelf --debug-dump=info --debug-dump=abbrev --debug-dump=aranges \
    --debug-dump=decodedline --debug-dump=Ranges --debug-dump=loc "$sidecar" \
    > "$work/readelf-dwarf.txt" 2>> "$work/readelf.stderr"
test ! -s "$work/readelf.stderr"
llvm-dwarfdump --verify "$sidecar" > "$work/llvm-verify.txt" 2>&1
dwarfdump "$sidecar" > "$work/dwarfdump.txt" 2> "$work/dwarfdump.stderr"
test ! -s "$work/dwarfdump.stderr"
gdb --nx --batch \
    -ex 'set pagination off' -ex 'set confirm off' -ex 'set debuginfod enabled off' \
    -ex "file $input" -ex 'set auto-solib-add off' -ex "symbol-file $sidecar" \
    -ex 'info functions gui_recovered_add' -ex 'ptype gui_recovered_add' \
    -ex 'list gui_recovered_add' -ex 'break gui_recovered_add' \
    -ex 'python exits=[]; gdb.events.exited.connect(lambda event: exits.append(event.exit_code))' \
    -ex run -ex 'python assert gdb.selected_frame().name() == "gui_recovered_add"' \
    -ex 'python import os; assert os.path.isfile(gdb.selected_frame().find_sal().symtab.fullname())' \
    -ex 'python before=int(gdb.parse_and_eval("$pc"))' -ex next \
    -ex 'python assert int(gdb.parse_and_eval("$pc")) != before' \
    -ex 'python before=int(gdb.parse_and_eval("$pc"))' -ex step \
    -ex 'python assert int(gdb.parse_and_eval("$pc")) != before' \
    -ex 'disable breakpoints' -ex continue -ex 'python assert exits == [0], exits' \
    -ex 'echo SCRIPT_MANAGER_GDB_PASS\n' > "$work/gdb.txt" 2> "$work/gdb.stderr"
test ! -s "$work/gdb.stderr"
grep -Fxq 'SCRIPT_MANAGER_GDB_PASS' "$work/gdb.txt"
if grep -Ei '^[[:space:]]*(warning:|Error|Traceback|AssertionError)|No such file' "$work/gdb.txt"; then
    exit 1
fi
printf '%s\n' 'script-manager-structural-validation=PASS' 'script-manager-gdb=PASS' \
    >> "$work/result.txt"
echo "gui-script-manager-integration=PASS"
