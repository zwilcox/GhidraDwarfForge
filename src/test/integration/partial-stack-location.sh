#!/usr/bin/env bash
set -euo pipefail
ghidra=$(realpath "${1:?Ghidra installation required}")
shift
native=("$@")
if (( ${#native[@]} == 0 )); then native=(--packaged-natives); fi
root=$(realpath "$(dirname "$0")/../../..")
work=$(mktemp -d "${TMPDIR:-/tmp}/forge-partial-stack.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
cd "$work"
gcc -nostdlib -no-pie -Wl,--build-id=sha1 "$root/src/test/fixtures/partial-stack.S" -o image
entry=$(nm image | awk '$3=="partial_stack" {print "0x"$1}')
sha256sum image >original.sha256
mkdir project
"$ghidra/support/analyzeHeadless" project Partial -import "$work/image" -deleteProject \
    -scriptPath "$root/src/test/integration/ghidra_scripts" -postScript PreparePartialStackParameter.java "$entry" \
    -postScript GhidraDwarfForge.java "${native[@]}" "--output=$work/partial.dbg" >export.log 2>&1
if ! grep -q 'partial-stack-first-instruction=PASS' export.log || ! grep -q 'GhidraDwarfForge symbol export PASS' export.log; then
    tail -n 50 export.log >&2
    exit 1
fi
python3 - <<'PYREPORT'
import json
from pathlib import Path

marker = "GhidraDwarfForge.java> GhidraDwarfForge report: "
records = [json.loads(line.split(marker, 1)[1].strip().removesuffix(" (GhidraScript)"))
           for line in Path("export.log").read_text().splitlines() if marker in line]
assert len(records) == 1 and records[0]["status"] == "PARTIAL", records
assert {"name": "overlay_only", "reason": "UNMAPPED_MEMORY"} in records[0]["skippedFunctions"]
PYREPORT
sha256sum --check original.sha256
llvm-dwarfdump --verify partial.dbg
readelf --debug-dump=loc partial.dbg >locations.txt
gdb -nx -q -batch -ex 'set debuginfod enabled off' -ex 'set auto-solib-add off' \
    -ex 'file image' -ex 'symbol-file partial.dbg' -ex 'python assert gdb.lookup_global_symbol("overlay_only") is None' \
    -ex "break *$entry" -ex run \
    -ex 'print stack_argument' -ex stepi -ex 'print stack_argument' \
    -ex 'printf "real_stack_argument=%d\n", *(int *)($rsp+40)' >runtime.txt 2>&1
if ! grep -Fqx '$1 = 23' runtime.txt || ! grep -Fqx '$2 = <optimized out>' runtime.txt ||
        ! grep -Fqx 'real_stack_argument=23' runtime.txt; then
    cat runtime.txt locations.txt >&2
    exit 1
fi
echo 'partial-stack-bounded-location=PASS'
