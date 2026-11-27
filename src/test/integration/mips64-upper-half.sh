#!/usr/bin/env bash
# Export a stripped ELF64 and debug its original upper-half code on a MIPS Malta board.
set -euo pipefail
sdk=$(realpath "${1:?Ghidra SDK required}")
endian=${2:?expected be or le}
results=${3:?test results directory required}
case "$endian" in
    be) prefix=mips-linux-gnu; emulation=elf64btsmip; emulator=qemu-system-mips64 ;;
    le) prefix=mipsel-linux-gnu; emulation=elf64ltsmip; emulator=qemu-system-mips64el ;;
    *) exit 2 ;;
esac
scripts=$(realpath "$(dirname "$0")")
fixtures=$(realpath "$scripts/../fixtures")
mkdir -p "$results"
case_dir=$(realpath "$(mktemp -d "$results/$endian.XXXXXXXX")")
cd "$case_dir"
echo "mips64-upper-half-results=$case_dir"
"$prefix-as" -64 -march=mips64r2 -mhard-float "$fixtures/mips64-upper-half.S" -o fixture.o
"$prefix-ld" -m "$emulation" -static --build-id=sha1 -z max-page-size=4096 \
    -T "$fixtures/mips64-upper-half.ld" -o reference fixture.o
"$prefix-objcopy" --strip-all reference original.elf
sha256sum original.elf > original.sha256
"$prefix-nm" -n --defined-only reference > symbols.txt
address_of() {
    awk -v name="$1" '$3 == name {print "0x" $1; found=1} END {exit !found}' symbols.txt
}
low=$(address_of low_entry)
high=$(address_of high_add)
word=$(address_of high_word)
boot=$(address_of boot_case)
readelf -hlAnW original.elf > original-metadata.txt
mkdir project
"$sdk/support/analyzeHeadless" "$case_dir/project" Split -deleteProject -import "$case_dir/original.elf" \
    -analysisTimeoutPerFile 120 -scriptPath "$scripts/ghidra_scripts" \
    -postScript PrepareUpperHalfFunctions.java "$low" "$high" "$word" \
    -postScript GhidraDwarfForge.java --packaged-natives > headless.log 2>&1
grep -Fq 'GhidraDwarfForge symbol export PASS' headless.log
python3 - <<'PY'
import json
from pathlib import Path

prefix = 'GhidraDwarfForge report: '
report, = [json.JSONDecoder().raw_decode(line.split(prefix, 1)[1])[0]
           for line in Path('headless.log').read_text().splitlines() if prefix in line]
assert report['failure'] is None and not report['failedFunctions'], report
PY
readelf -hSWn --debug-dump=info,aranges,decodedline,loc original.elf.dbg > readelf.txt 2> readelf.stderr
test ! -s readelf.stderr
original_id=$(awk '/Build ID:/ {print $NF}' original-metadata.txt)
[[ $original_id =~ ^[[:xdigit:]]{40}$ && $(awk '/Build ID:/ {print $NF}' readelf.txt) == "$original_id" ]]
llvm-dwarfdump --verify original.elf.dbg > llvm.txt
grep -Fq 'No errors.' llvm.txt
python3 "$scripts/check-dwarfdump.py" original.elf.dbg strict.txt --original original.elf

sockets=$(mktemp -d "${TMPDIR:-/tmp}/forge-mips64.XXXXXXXX")
socket=$sockets/gdb
qemu_pid=
cleanup() {
    if [[ -n $qemu_pid ]]; then
        kill "$qemu_pid" 2>/dev/null || true
        wait "$qemu_pid" 2>/dev/null || true
    fi
    rm -rf -- "$sockets"
}
trap cleanup EXIT
# ELF load addresses select physical RAM. Start the CPU at the ELF's virtual entry.
"$emulator" -M malta -cpu MIPS64R2-generic -m 128 -display none -vga none -serial none \
    -monitor none -nic none -device "loader,file=$case_dir/original.elf" \
    -device "loader,addr=$boot,cpu-num=0" -S -gdb "unix:$socket,server=on,wait=off" > qemu.log 2>&1 &
qemu_pid=$!
for ((i=0; i<100; i++)); do
    if [[ -S $socket ]]; then break; fi
    kill -0 "$qemu_pid"
    sleep 0.1
done
test -S "$socket"
(cd "$sockets" && FORGE_MIPS64_CASE="$case_dir" FORGE_MIPS64_SOCKET="$socket" \
    timeout 45s gdb-multiarch -q -nx -batch -ex 'set debuginfod enabled off' -ex 'set auto-solib-add off' \
    -x "$scripts/mips64-upper-half-gdb.py") > gdb.log 2>&1
grep -Fxq 'mips64-upper-half-gdb=PASS' gdb.log
sha256sum --check original.sha256
echo "mips64-upper-half=PASS endian=$endian"
