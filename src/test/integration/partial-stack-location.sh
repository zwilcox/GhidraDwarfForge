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
storage=$(nm image | awk '$3=="scope_storage" {print "0x"$1}')
sha256sum image >original.sha256
mkdir project
"$ghidra/support/analyzeHeadless" project Partial -import "$work/image" -deleteProject \
    -scriptPath "$root/src/test/integration/ghidra_scripts" -postScript PreparePartialStackParameter.java "$entry" "$storage" \
    -postScript GhidraDwarfForge.java "${native[@]}" "--output=$work/partial.dbg" >export.log 2>&1
if ! grep -q 'partial-stack-first-instruction=PASS' export.log || ! grep -q 'GhidraDwarfForge symbol export PASS' export.log; then
    tail -n 50 export.log >&2
    exit 1
fi
python3 - "$entry" <<'PYREPORT'
import json
import sys
from pathlib import Path

marker = "GhidraDwarfForge.java> GhidraDwarfForge report: "
records = [json.loads(line.split(marker, 1)[1].strip().removesuffix(" (GhidraScript)"))
           for line in Path("export.log").read_text().splitlines() if marker in line]
assert len(records) == 1 and records[0]["status"] == "PARTIAL", records
assert {"name": "overlay_only", "reason": "UNMAPPED_MEMORY"} in records[0]["skippedFunctions"]
for name in ("partial_stack", "analysis_block_only"):
    assert {"name": name, "reason": "UNMAPPED_MEMORY"} in records[0]["skippedFunctions"]
assert any("bank_private" in message and "owning function was not exported" in message
           for message in records[0]["diagnostics"])
assert not any("Source coverage unavailable for partial_stack" in message for message in records[0]["diagnostics"])
functions = [f for f in records[0]["coverage"]["functions"] if f["name"] == "partial_stack"]
assert len(functions) == 1, functions
source = functions[0]["source"]
assert source["decodedInstructions"] == "1", source
assert [int(address, 16) for address in source["decodedStarts"]] == [int(sys.argv[1], 16)], source
PYREPORT
sha256sum --check original.sha256
llvm-dwarfdump --verify partial.dbg
readelf -h -S --debug-dump=info,abbrev,aranges,decodedline partial.dbg >structure.txt
if [[ -n ${DWARFDUMP:-} ]]; then
    python3 "$root/src/test/integration/check-dwarfdump.py" partial.dbg strict.log --tool "$DWARFDUMP" --original image
fi
readelf --debug-dump=loc partial.dbg >locations.txt
cat >verify.gdb <<'GDB'
set debuginfod enabled off
set auto-solib-add off
file image
symbol-file partial.dbg
python
assert not gdb.lookup_static_symbols("overlay_only"), "unexpected file-local overlay symbol"
assert gdb.lookup_global_symbol("overlay_only") is None, "unexpected global overlay symbol"
assert gdb.lookup_global_symbol("analysis_block_only") is None and not gdb.lookup_static_symbols("analysis_block_only")
entry = int(gdb.parse_and_eval("$fixture_entry"))
for address in range(entry, entry + 32):
    block = gdb.block_for_pc(address)
    assert block and block.function and block.function.name == "partial_stack", hex(address)
assert gdb.lookup_symbol("real_private", block)[0] is not None, "lost default-space static"
assert gdb.lookup_symbol("bank_private", block)[0] is None, "overlay static assigned to default-space function"
end
break *$fixture_entry
run
print stack_argument
stepi
print stack_argument
printf "real_stack_argument=%d\n", *(int *)($rsp+40)
GDB
if ! gdb -nx -q -batch -ex "set \$fixture_entry = $entry" -x verify.gdb >runtime.txt 2>&1; then
    cat runtime.txt >&2
    exit 1
fi
if ! grep -Fqx '$1 = 23' runtime.txt || ! grep -Fqx '$2 = <optimized out>' runtime.txt ||
        ! grep -Fqx 'real_stack_argument=23' runtime.txt; then
    cat runtime.txt locations.txt >&2
    exit 1
fi
echo 'partial-stack-bounded-location=PASS'
