#!/usr/bin/env bash
set -euo pipefail

ghidra_dir=$(realpath "${1:?Ghidra installation required}")
consumer=$(realpath "${2:?libdwarf required}")
producer=$(realpath "${3:?libdwarfp required}")
repo=$(realpath "$(dirname "$0")/../../..")
work=$(mktemp -d "${TMPDIR:-/tmp}/forge-upper-half-elf.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
cd "$work"

# Link a normal x86-64 ELF at a kernel address. It is only imported, never run.
printf '%s\n' '.text' '.globl _start' '.type _start,@function' '_start: ret' |
    as --64 -o entry.o
ld -m elf_x86_64 -Ttext=0xffffffff81000000 -e _start -o kernel.elf entry.o
readelf -lW kernel.elf >segments
awk '$1 == "LOAD" && $3 == "0xffffffff81000000" && / E / {found=1} END {exit !found}' segments
cp kernel.elf original.elf
printf '%s\n' 'previous sidecar' >previous.dbg
printf '%s\n' 'previous source' >previous.c

expect_rejection() {
    local log="$work/$1.log" status=0
    "$repo/support/ghidra-dwarf-forge-headless" --ghidra-dir="$ghidra_dir" \
        --import="$work/kernel.elf" --libdwarf="$consumer" --libdwarfp="$producer" \
        --log="$log" >wrapper.log 2>&1 || status=$?
    if [[ $status != 10 ]]; then
        tail -n 40 wrapper.log >&2
        return 1
    fi
    python3 - "$log" <<'PYREPORT'
import json
import pathlib
import sys

marker = "GhidraDwarfForge.java> GhidraDwarfForge report: "
reports = [json.loads(line.split(marker, 1)[1].rstrip().removesuffix(" (GhidraScript)"))
           for line in pathlib.Path(sys.argv[1]).read_text().splitlines() if marker in line]
assert len(reports) == 1, reports
report = reports[0]
assert report["status"] == "FATAL", report
assert report["failure"]["message"] == (
    "ELF64 virtual address 0xffffffff81000000 is valid. "
    "GhidraDwarfForge does not yet support upper-half addresses. ELF header field: e_entry"
), report["failure"]
PYREPORT
    cmp original.elf kernel.elf
}

cp previous.dbg kernel.elf.dbg
cp previous.c kernel.elf.dbg.c
expect_rejection existing-outputs
cmp previous.dbg kernel.elf.dbg
cmp previous.c kernel.elf.dbg.c
rm -- kernel.elf.dbg kernel.elf.dbg.c
expect_rejection absent-outputs
for path in kernel.elf.dbg kernel.elf.dbg.c; do
    [[ ! -e "$path" && ! -L "$path" ]]
done
echo 'upper-half-elf-rejection=PASS'
