#!/usr/bin/env bash
# Shared helpers for layout tests; sourced by their artifact-owning harnesses.

layout_compiler_oracle() (
    set -euo pipefail
    local target=$1 reference=$2 destination=$3
    local emulator= sysroot= emulator_pid= port
    local commands=()
    port=$((28000 + (BASHPID % 20000)))
    case "$target" in
        x86_64) commands=(-ex run) ;;
        aarch64) emulator=qemu-aarch64-static; sysroot=/usr/aarch64-linux-gnu ;;
        arm32) emulator=qemu-arm-static; sysroot=/usr/arm-linux-gnueabihf ;;
        mips32be) emulator=qemu-mips-static; sysroot=/usr/mips-linux-gnu ;;
        mips32le) emulator=qemu-mipsel-static; sysroot=/usr/mipsel-linux-gnu ;;
        *) echo "unknown oracle target: $target" >&2; exit 2 ;;
    esac
    cleanup_oracle() {
        if [[ -n "$emulator_pid" ]] && kill -0 "$emulator_pid" 2>/dev/null; then
            kill "$emulator_pid" 2>/dev/null || true
            wait "$emulator_pid" 2>/dev/null || true
        fi
    }
    trap cleanup_oracle EXIT
    if [[ -n "$emulator" ]]; then
        "$emulator" -L "$sysroot" -g "$port" "$reference" \
            >"$destination.emulator.txt" 2>&1 &
        emulator_pid=$!
        sleep 0.2
        commands=(-ex "set sysroot $sysroot" -ex "target remote :$port" -ex continue)
    fi
    timeout 30s gdb-multiarch -q -nx -batch \
        -ex 'set debuginfod enabled off' -ex 'set auto-solib-add off' \
        -ex "directory $(realpath "$(dirname "${BASH_SOURCE[0]}")/../fixtures")" \
        -ex 'set disable-randomization off' -ex "file $reference" \
        -ex 'break recovered_add' "${commands[@]}" \
        -ex 'ptype recovered_add' -ex 'print fixture_sink' -ex continue \
        >"$destination" 2>&1
    if [[ -n "$emulator_pid" ]]; then
        wait "$emulator_pid"
        emulator_pid=
    fi
    grep -Fq 'Breakpoint 1,' "$destination"
    grep -Fq 'type = int (int, int, int, int)' "$destination"
    grep -Fq 'exited normally' "$destination"
    # This independent compiler-DWARF run establishes whether the exact QEMU
    # vDSO warning is environmental before any Forge result can allow it.
    layout_validate_gdb_diagnostics "$destination" "$reference" compiler "$target" "$destination"
)

layout_validate_gdb_diagnostics() {
    local transcript=$1 original=$2 variant=$3 target=$4 oracle=$5
    local allow_vdso=0
    local vdso='^warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ has a corrupt string table index$'
    if [[ "$target" == aarch64 || "$target" == arm32 ]] &&
            [[ -f "$oracle" ]] && grep -Eq "$vdso" "$oracle"; then
        allow_vdso=1
    fi
    awk -v variant="$variant" -v allow_vdso="$allow_vdso" -v vdso="$vdso" \
        -v allowed="warning: BFD: warning: $original has a corrupt string table index" '
        variant == "no-section-names" && $0 == allowed { next }
        allow_vdso && $0 ~ vdso { next }
        tolower($0) ~ /warning:|error:|malformed|corrupt|could not find/ { print; failed = 1 }
        END { exit failed }
    ' "$transcript"
}
