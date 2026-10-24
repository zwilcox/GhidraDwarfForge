#!/usr/bin/env bash
set -euo pipefail

# Research only: read source-built fixtures, mutate only newly created private copies.
if [[ $# -lt 1 ]]; then
    echo "usage: $0 <source-built-fixture-directory> [target ...]" >&2
    exit 64
fi
repository=$(realpath "$(dirname "$0")/../../../..")
fixtures=$(realpath "$1")
shift
targets=("$@")
if [[ ${#targets[@]} -eq 0 ]]; then
    targets=(x86_64 aarch64 mips32be mips32le)
fi
root="$repository/build/test-results/debuglink-research"
mkdir -p "$root"
work=$(mktemp -d "$root/run.XXXXXXXX")
mkdir -p "$work/classes"
echo "debuglink-research-results=$work"
javac --release 21 -d "$work/classes" \
    "$repository/src/main/java/ghidradwarfforge/elf/ElfImage.java" \
    "$repository/src/test/research/debuglink/DebuglinkToolProbe.java"
printf 'target\trole\ttool_exit\tload_crc_probe\n' > "$work/summary.tsv"
for target in "${targets[@]}"; do
    case "$target" in
        x86_64) tool=objcopy ;;
        aarch64) tool=aarch64-linux-gnu-objcopy ;;
        arm32) tool=arm-linux-gnueabihf-objcopy ;;
        mips32be) tool=mips-linux-gnu-objcopy ;;
        mips32le) tool=mipsel-linux-gnu-objcopy ;;
        *) echo "unknown research fixture profile: $target" >&2; exit 64 ;;
    esac
    command -v "$tool" >/dev/null
    "$tool" --version > "$work/$target-tool.txt"
    for role in exec.stripped pie.stripped exec.no-sections.stripped \
            exec.no-section-names exec.extended-programs; do
        original="$fixtures/$target/semantic.$role"
        if [[ ! -f "$original" ]]; then
            printf '%s\t%s\tMISSING_FIXTURE\tNOT_RUN\n' "$target" "$role" >> "$work/summary.tsv"
            continue
        fi
        case_dir="$work/$target/$role"
        mkdir -p "$case_dir"
        sha256sum "$original" >> "$work/originals.sha256"
        cp --preserve=all "$original" "$case_dir/original"
        reference_role=exec
        if [[ "$role" == pie.* ]]; then reference_role=pie; fi
        cp "$fixtures/$target/semantic.$reference_role.reference" "$case_dir/fixture.debug"
        status=0
        "$tool" "--add-gnu-debuglink=$case_dir/fixture.debug" "$case_dir/original" \
            "$case_dir/candidate" > "$case_dir/objcopy.stdout" 2> "$case_dir/objcopy.stderr" || status=$?
        probe=NOT_RUN
        if [[ "$status" == 0 ]]; then
            probe=PASS
            java -cp "$work/classes" ghidradwarfforge.elf.DebuglinkToolProbe \
                "$case_dir/original" "$case_dir/candidate" "$case_dir/fixture.debug" \
                > "$case_dir/probe.txt" 2>&1 || probe=REJECTED
        fi
        printf '%s\t%s\t%s\t%s\n' "$target" "$role" "$status" "$probe" >> "$work/summary.tsv"
        cmp "$original" "$case_dir/original"
    done
done
# Objcopy computes a CRC for arbitrary bytes; it is not an ELF identity validator.
case_dir="$work/wrong-debug-file"
mkdir -p "$case_dir"
cp "$fixtures/x86_64/semantic.exec.stripped" "$case_dir/original"
printf 'not an ELF debug artifact\n' > "$case_dir/unrelated.debug"
objcopy "--add-gnu-debuglink=$case_dir/unrelated.debug" "$case_dir/original" \
    "$case_dir/candidate" > "$case_dir/objcopy.stdout" 2> "$case_dir/objcopy.stderr"
java -cp "$work/classes" ghidradwarfforge.elf.DebuglinkToolProbe \
    "$case_dir/original" "$case_dir/candidate" "$case_dir/unrelated.debug" > "$case_dir/probe.txt"
sha256sum -c "$work/originals.sha256" > "$work/original-preservation.txt"
cat "$work/summary.tsv"
echo 'wrong-debug-file-accepted-by-objcopy=CONFIRMED (product must reject independently)'
echo debuglink-backend-research=PASS
