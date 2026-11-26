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

layout=${4:-kernel}
compile_options=()
case "$layout" in
    kernel) link_address=0xffffffff81000000; modes=(linked rebased) ;;
    crossing)
        # Place nonzero_add first so its instructions and variable locations span bit 63.
        link_address=0x7ffffffffffffff8
        compile_options=(-ffunction-sections -falign-functions=1)
        modes=(crossing)
        ;;
    *) echo "unknown ELF layout: $layout" >&2; exit 2 ;;
esac
gcc -O0 -g -gdwarf-5 -ffreestanding -fno-stack-protector -fno-omit-frame-pointer \
    -fno-pie -no-pie -mcmodel=kernel -nostdlib -Wl,--build-id=sha1 \
    "${compile_options[@]}" "-Wl,--defsym=forge_text_address=$link_address" "-Wl,-T,$fixtures/nonzero_load_offset.ld" \
    "$fixtures/upper_half_stack.c" "$fixtures/nonzero_load_offset.c" -o reference
objcopy --strip-all reference kernel.elf
cp kernel.elf original.elf
readelf -lW kernel.elf > segments
awk -v address="$link_address" '$1 == "LOAD" && $3 == address && / E / {found=1} END {exit !found}' segments
address_of() {
    nm -n --defined-only reference | awk -v name="$1" '$3 == name {print "0x" $1; found=1} END {exit !found}'
}
function_address=$(address_of nonzero_add)
global_address=$(address_of nonzero_sink)
stack_address=$(address_of kernel_stack_argument)
stack_size=$(nm -n -S --defined-only reference | awk '$4 == "kernel_stack_argument" {print "0x" $2; found=1} END {exit !found}')
mapfile -t stack_changes < <(objdump -d --no-show-raw-insn --disassemble=kernel_stack_argument reference |
    awk '/^[[:space:]]*[[:xdigit:]]+:/ {
        if (changed) { sub(/:$/, "", $1); print "0x" $1 }
        changed = (($2 == "push" || $2 == "pop") && $3 == "%rbp")
    }')
test "${#stack_changes[@]}" -eq 2
function_size=$(nm -n -S --defined-only reference | awk '$4 == "nonzero_add" {print "0x" $2; found=1} END {exit !found}')

# Resolve the sidecar from another directory so GDB also verifies the source location.
mkdir projects debugger
cat > debugger/verify.gdb <<GDB
set debuginfod enabled off
set auto-solib-add off
file $work/kernel.elf
source $work/kernel.elf.dbg.gdb.py
symbol-file $work/kernel.elf.dbg
python
import re
if '$layout' == 'crossing':
    assert $function_address < (1 << 63) < $function_address + $function_size
    for pc in ((1 << 63) - 1, 1 << 63):
        line = gdb.find_pc_line(pc)
        assert line.line > 0 and line.symtab.fullname() == '$work/kernel.elf.dbg.c'
assert int(gdb.parse_and_eval('(unsigned long)&nonzero_add')) == $function_address
assert int(gdb.parse_and_eval('(unsigned long)&nonzero_sink')) == $global_address
assert int(gdb.parse_and_eval('(unsigned long)&kernel_stack_argument')) == $stack_address
bp = gdb.Breakpoint('*nonzero_add')
assert int(bp.locations[0].address) == $function_address
sal = gdb.find_pc_line($function_address)
assert sal.line > 0 and sal.symtab.fullname() == '$work/kernel.elf.dbg.c'
for pc in ($function_address, $function_address + $function_size - 1):
    scope = gdb.execute('info scope *%#x' % pc, to_string=True)
    for parameter, register in [('left', 'rdi'), ('right', 'rsi')]:
        assert f'Symbol {parameter} is a variable in \$' + register + ', length 4.' in scope, scope
stack_scope = gdb.execute('info scope *%#x' % $stack_address, to_string=True)
stack_value = stack_scope.split('Symbol stack_value ', 1)[1].split('\nSymbol ', 1)[0]
rows = re.findall(r'Range (0x[0-9a-f]+)-(0x[0-9a-f]+):[^\n]*\n\s*0: DW_OP_bregx register 7 [^\n]* offset (\d+)', stack_value)
observed = [(int(low, 16), int(high, 16), int(offset)) for low, high, offset in rows]
assert observed == [($stack_address, ${stack_changes[0]}, 8), (${stack_changes[0]}, ${stack_changes[1]}, 16),
    (${stack_changes[1]}, $stack_address + $stack_size, 8)], stack_value
end
list nonzero_add
info scope *$function_address
GDB

for mode in "${modes[@]}"; do
    cd "$work"
    prepare=()
    delta=0
    if [[ $mode == rebased ]]; then
        delta=-0x7ffffffffffff000
        prepare=(-postScript RebaseFixtureProgram.java "$delta")
    fi
    analyzed_function=$(printf '0x%x' "$((function_address + delta))")
    analyzed_global=$(printf '0x%x' "$((global_address + delta))")
    analyzed_stack=$(printf '0x%x' "$((stack_address + delta))")
    "$ghidra_dir/support/analyzeHeadless" "$work/projects" "HighElf_$mode" -deleteProject -import "$work/kernel.elf" \
        -analysisTimeoutPerFile 120 -scriptPath "$repo/src/test/integration/ghidra_scripts" \
        "${prepare[@]}" -postScript PrepareNonzeroLoadOffset.java "$analyzed_function" "$analyzed_global" "$analyzed_stack" \
        -postScript GhidraDwarfForge.java "--libdwarf=$consumer" "--libdwarfp=$producer" --gdb-loader \
        > headless.log 2>&1 || { tail -80 headless.log >&2; exit 1; }
    grep -Fq 'GhidraDwarfForge symbol export PASS' headless.log || { tail -80 headless.log >&2; exit 1; }
    grep -Fq "Ghidra-to-ELF address delta: $(printf '0x%x' "$delta")" headless.log
    cmp original.elf kernel.elf
    test -s kernel.elf.dbg.c
    readelf -hSW kernel.elf.dbg > headers
    readelf --debug-dump=info,decodedline,loc kernel.elf.dbg > dwarf.txt 2> warnings
    test ! -s warnings || { cat warnings >&2; exit 1; }
    llvm-dwarfdump --verify kernel.elf.dbg
    python3 "$repo/src/test/integration/check-dwarfdump.py" kernel.elf.dbg validator.txt --original kernel.elf
    cd debugger
    gdb-multiarch -q -nx -batch -x verify.gdb > gdb.txt 2>&1 || { cat gdb.txt >&2; exit 1; }
    cat gdb.txt
    grep -Fq 'Forge companion registered: forge-load' gdb.txt
    grep -Eq 'int nonzero_add\(' gdb.txt
    cmp "$work/original.elf" "$work/kernel.elf"
    echo "upper-half-elf=PASS $mode static GDB function, breakpoint, source, global, register and stack parameters"
done

if [[ $layout == crossing ]]; then exit 0; fi
# Corrupt only the data section's virtual extent in a disposable input.
cd "$work"
python3 - <<'PYELF'
from pathlib import Path
import struct

image = bytearray(Path("original.elf").read_bytes())
shoff, = struct.unpack_from("<Q", image, 40)
width, count, names = struct.unpack_from("<HHH", image, 58)
strings, = struct.unpack_from("<Q", image, shoff + names * width + 24)
for index in range(count):
    section = shoff + index * width
    name, = struct.unpack_from("<I", image, section)
    if image.startswith(b".data\0", strings + name):
        size, = struct.unpack_from("<Q", image, section + 32)
        assert size >= 2
        struct.pack_into("<Q", image, section + 16, (1 << 64) - 1)
        break
else:
    raise AssertionError("missing fixture data section")
Path("wrapping.elf").write_bytes(image)
PYELF
cp wrapping.elf wrapping.original
for existing in yes no; do
    if [[ "$existing" == yes ]]; then
        cp kernel.elf.dbg wrapping.elf.dbg
        cp kernel.elf.dbg.c wrapping.elf.dbg.c
    else
        rm -- wrapping.elf.dbg wrapping.elf.dbg.c
    fi
    status=0
    "$repo/support/ghidra-dwarf-forge-headless" --ghidra-dir="$ghidra_dir" \
        --import="$work/wrapping.elf" --libdwarf="$consumer" --libdwarfp="$producer" \
        --log="$work/wrapping-$existing.log" > wrapper.log 2>&1 || status=$?
    if [[ $status != 10 ]] || ! grep -Fq 'ELF64 virtual address range wraps at sh_addr' "wrapping-$existing.log"; then
        tail -40 wrapper.log >&2
        exit 1
    fi
    cmp wrapping.original wrapping.elf
    if [[ "$existing" == yes ]]; then
        cmp kernel.elf.dbg wrapping.elf.dbg
        cmp kernel.elf.dbg.c wrapping.elf.dbg.c
    else
        for path in wrapping.elf.dbg wrapping.elf.dbg.c; do [[ ! -e "$path" && ! -L "$path" ]]; done
    fi
done
echo 'wrapping-elf=PASS input and prior outputs preserved, absent outputs stay absent'
