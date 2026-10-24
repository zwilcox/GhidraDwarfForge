#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
    echo "usage: $0 <ghidra-dir> <installed-extension-module> <fixture.stripped> <fixture.reference>" >&2
    echo "requires Linux, Xvfb (or XVFB_BIN), Openbox (or OPENBOX_BIN), xprop/xwininfo, GUI Java 21+ (or JAVA_BIN), javac, Python 3, GNU/LLVM/libdwarf and GDB" >&2
    exit 64
fi
repository=$(realpath "$(dirname "$0")/../../..")
ghidra=$(realpath "$1")
module=$(realpath "$2")
fixture=$(realpath "$3")
reference=$(realpath "$4")
xvfb=${XVFB_BIN:-Xvfb}
openbox=${OPENBOX_BIN:-openbox}
java=${JAVA_BIN:-java}
for dependency in "$xvfb" "$openbox" xprop xwininfo "$java" javac python3 readelf llvm-dwarfdump dwarfdump gdb timeout; do
    command -v "$dependency" >/dev/null
done
test -s "$module/ghidra_scripts/GhidraDwarfForge.java"
test -s "$module/ghidra_scripts/ExportGhidraDwarfForge.java"
(cd "$module" && sha256sum -c RELEASE-SHA256SUMS) >/dev/null
root="$repository/build/test-results/gui-script-manager"
mkdir -p "$root"
work=$(mktemp -d "$root/run.XXXXXXXX")
mkdir -p "$work/classes" "$work/settings" "$work/cache" "$work/tmp" "$work/user" \
    "$work/wm-config" "$work/wm-cache"
echo "gui-script-manager-results=$work"
cleanup() {
    if [[ -n ${openbox_pid:-} ]]; then
        kill "$openbox_pid" 2>/dev/null || true
        wait "$openbox_pid" 2>/dev/null || true
    fi
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
    "$repository/src/test/integration/gui/GuiWindowGeometrySmoke.java" \
    "$repository/src/test/integration/gui/GuiTableClickSmoke.java" \
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
# Bare Xvfb can leave decorated JFrame coordinates inconsistent with native X11
# placement. Own a real WM on this private display; never use the user's desktop.
python3 - "$work" <<'PY'
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

work = Path(sys.argv[1])
menu = ET.Element("openbox_menu", xmlns="http://openbox.org/3.4/menu")
ET.SubElement(menu, "menu", id="root-menu", label="GUI validation")
ET.ElementTree(menu).write(work / "openbox-menu.xml", encoding="utf-8", xml_declaration=True)
config = ET.Element("openbox_config", xmlns="http://openbox.org/3.4/rc")
ET.SubElement(ET.SubElement(config, "theme"), "name").text = "Clearlooks"
focus = ET.SubElement(config, "focus")
ET.SubElement(focus, "focusNew").text = "yes"
ET.SubElement(focus, "followMouse").text = "no"
ET.SubElement(ET.SubElement(config, "menu"), "file").text = str(work / "openbox-menu.xml")
ET.ElementTree(config).write(work / "openbox.xml", encoding="utf-8", xml_declaration=True)
PY
"$openbox" --version > "$work/openbox-version.txt" 2>&1
DISPLAY=":$display" XDG_CONFIG_HOME="$work/wm-config" XDG_CACHE_HOME="$work/wm-cache" \
    "$openbox" --sm-disable --config-file "$work/openbox.xml" \
    >"$work/openbox.log" 2>&1 &
openbox_pid=$!
for attempt in {1..100}; do
    kill -0 "$openbox_pid"
    LC_ALL=C DISPLAY=":$display" xprop -root _NET_SUPPORTING_WM_CHECK > "$work/wm-ready.txt"
    if grep -Eq '^_NET_SUPPORTING_WM_CHECK\(WINDOW\): window id # 0x[1-9a-fA-F][0-9a-fA-F]*$' "$work/wm-ready.txt"; then
        break
    fi
    sleep 0.1
done
grep -Eq '^_NET_SUPPORTING_WM_CHECK\(WINDOW\): window id # 0x[1-9a-fA-F][0-9a-fA-F]*$' "$work/wm-ready.txt"
DISPLAY=":$display" timeout 60 "$java" -Djava.awt.headless=false \
    -Duser.home="$work/user" -Djava.io.tmpdir="$work/tmp" \
    -cp "$work/classes" GuiWindowGeometrySmoke "$work/native-geometry" \
    > "$work/native-geometry.log" 2>&1
function_address=$(readelf -Ws "$reference" | awk '$8 == "recovered_add" && !found++ { print $2 }')
test -n "$function_address"
DISPLAY=":$display" timeout 300 "$java" --enable-native-access=ALL-UNNAMED \
    -Djava.awt.headless=false -Duser.home="$work/user" \
    -Dapplication.settingsdir="$work/settings" -Dapplication.cachedir="$work/cache" \
    -Dapplication.tempdir="$work/tmp" -Djava.io.tmpdir="$work/tmp" \
    -cp "$work/classes:$classpath" GuiScriptManagerSmoke \
    "$ghidra" "$module" "$fixture" "$work" "$function_address" \
    2>&1 | tee "$work/gui.log"
kill -0 "$openbox_pid"
input="$work/select/readonly/fixture"
sidecar="$work/select/chosen/fixture.dbg"
readelf -h -S -n "$input" > "$work/input-elf.txt" 2> "$work/readelf.stderr"
readelf -h -S -n "$sidecar" > "$work/sidecar-elf.txt" 2>> "$work/readelf.stderr"
readelf --debug-dump=info --debug-dump=abbrev --debug-dump=aranges \
    --debug-dump=decodedline --debug-dump=Ranges --debug-dump=loc "$sidecar" \
    > "$work/readelf-dwarf.txt" 2>> "$work/readelf.stderr"
test ! -s "$work/readelf.stderr"
llvm-dwarfdump --verify "$sidecar" > "$work/llvm-verify.txt" 2>&1
python3 "$repository/src/test/integration/check-dwarfdump.py" \
    "$sidecar" "$work/dwarfdump.txt" --original "$input"
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
