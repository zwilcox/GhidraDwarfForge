#!/usr/bin/env bash
set -euo pipefail

ghidra_dir=$(realpath "${1:?Ghidra installation required}")
consumer=$(realpath "${2:?libdwarf required}")
producer=$(realpath "${3:?libdwarfp required}")
repo=$(realpath "$(dirname "$0")/../../..")
fixtures="$repo/src/test/fixtures"
work=$(mktemp -d "${TMPDIR:-/tmp}/forge-upper-half-elf.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
cd "$work"

# This image is linked at kernel addresses. Linux userspace cannot execute it.
gcc -O0 -g -gdwarf-5 -ffreestanding -fno-stack-protector -fno-omit-frame-pointer \
    -fno-pie -no-pie -mcmodel=kernel -nostdlib -Wl,--build-id=sha1 \
    -Wl,--defsym=forge_text_address=0xffffffff81000000 "-Wl,-T,$fixtures/nonzero_load_offset.ld" \
    "$fixtures/nonzero_load_offset_start.S" "$fixtures/nonzero_load_offset.c" -o reference
objcopy --strip-all reference kernel.elf
cp kernel.elf original.elf
readelf -lW kernel.elf > segments
awk '$1 == "LOAD" && $3 == "0xffffffff81000000" && / E / {found=1} END {exit !found}' segments
address_of() {
    nm -n --defined-only reference | awk -v name="$1" '$3 == name {print "0x" $1; found=1} END {exit !found}'
}
function_address=$(address_of nonzero_add)
global_address=$(address_of nonzero_sink)

mkdir projects
"$ghidra_dir/support/analyzeHeadless" "$work/projects" HighElf -deleteProject -import "$work/kernel.elf" \
    -analysisTimeoutPerFile 120 -scriptPath "$repo/src/test/integration/ghidra_scripts" \
    -postScript PrepareNonzeroLoadOffset.java "$function_address" "$global_address" \
    -postScript GhidraDwarfForge.java "--libdwarf=$consumer" "--libdwarfp=$producer" \
    > headless.log 2>&1 || { tail -40 headless.log >&2; exit 1; }
grep -Fq 'GhidraDwarfForge symbol export PASS' headless.log || { tail -40 headless.log >&2; exit 1; }
cmp original.elf kernel.elf
test -s kernel.elf.dbg.c
readelf -hSW kernel.elf.dbg > headers
readelf --debug-dump=info,decodedline,loc kernel.elf.dbg > dwarf.txt 2> warnings
test ! -s warnings || { cat warnings >&2; exit 1; }
llvm-dwarfdump --verify kernel.elf.dbg
python3 "$repo/src/test/integration/check-dwarfdump.py" kernel.elf.dbg validator.txt --original kernel.elf

# Resolve the sidecar from another directory so GDB also verifies the source location.
mkdir debugger
cd debugger
gdb-multiarch -q -nx -batch -ex 'set debuginfod enabled off' -ex 'set auto-solib-add off' \
    -ex "file $work/kernel.elf" -ex "symbol-file $work/kernel.elf.dbg" \
    -ex "python assert int(gdb.parse_and_eval('(unsigned long)&nonzero_add')) == $function_address" \
    -ex "python assert int(gdb.parse_and_eval('(unsigned long)&nonzero_sink')) == $global_address" \
    -ex "python bp = gdb.Breakpoint('*nonzero_add'); assert int(bp.locations[0].address) == $function_address" \
    -ex "python sal = gdb.find_pc_line($function_address); assert sal.line > 0 and sal.symtab.fullname() == '$work/kernel.elf.dbg.c'" \
    -ex 'list nonzero_add' > gdb.txt
grep -Eq 'int nonzero_add\(' gdb.txt
cmp "$work/original.elf" "$work/kernel.elf"
echo 'upper-half-elf=PASS static GDB symbol, breakpoint, source and global address'
