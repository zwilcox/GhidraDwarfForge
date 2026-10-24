#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <source-built-arm32-stripped-elf> <reference-elf>" >&2
    exit 64
fi
repository_dir=$(realpath "$(dirname "$0")/../../..")
input=$(realpath "$1")
reference=$(realpath "$2")
root="$repository_dir/build/test-results/arm-ehabi-regression"
mkdir -p "$root"
work=$(mktemp -d "$root/run.XXXXXXXX")
checker="$repository_dir/src/test/integration/verify-arm-ehabi.py"
sha256sum "$input" "$reference" > "$work/originals.sha256"
readelf --debug-dump=frames "$input" > "$work/old-frames.txt" 2> "$work/old-frames.stderr"
test ! -s "$work/old-frames.stderr"
if grep -Fq ' FDE ' "$work/old-frames.txt"; then
    echo 'regression fixture unexpectedly contains DWARF FDEs' >&2
    exit 1
fi
"$checker" "$input" "$reference" "$work/valid"

arm-linux-gnueabihf-objcopy --dump-section ".ARM.exidx=$work/index.bin" \
    "$input" "$work/dump-copy.elf"
python3 - "$work" <<'PY'
from pathlib import Path
import sys
work = Path(sys.argv[1])
data = (work / 'index.bin').read_bytes()
assert len(data) > 0 and len(data) % 8 == 0
(work / 'truncated.bin').write_bytes(data[:-1])
# The documented ARMv7 little-endian fixture now has no usable unwind rule.
missing = bytearray(data)
for offset in range(4, len(missing), 8):
    missing[offset:offset + 4] = (1).to_bytes(4, 'little')
(work / 'cantunwind.bin').write_bytes(missing)
# A structurally decoded compact entry can still explicitly refuse to unwind.
refused = bytearray(data)
for offset in range(4, len(refused), 8):
    refused[offset:offset + 4] = (0x808000b0).to_bytes(4, 'little')
(work / 'refuse.bin').write_bytes(refused)
PY
arm-linux-gnueabihf-objcopy --remove-section=.ARM.exidx --remove-section=.ARM.extab \
    "$input" "$work/absent.elf"
for variant in truncated cantunwind refuse; do
    arm-linux-gnueabihf-objcopy --update-section ".ARM.exidx=$work/$variant.bin" \
        "$input" "$work/$variant.elf"
done
for variant in absent truncated cantunwind refuse; do
    if "$checker" "$work/$variant.elf" "$reference" "$work/$variant" \
            > "$work/$variant.log" 2>&1; then
        echo "invalid ARM unwind fixture accepted: $variant" >&2
        exit 1
    fi
done
grep -Fq 'missing or malformed ARM EHABI index' "$work/absent.log"
grep -Fq 'missing or malformed ARM EHABI index' "$work/truncated.log"
grep -Fq 'missing decoded ARM EHABI coverage' "$work/cantunwind.log"
grep -Fq 'missing decoded ARM EHABI coverage' "$work/refuse.log"
sha256sum -c "$work/originals.sha256" > "$work/original-preservation.txt"
printf '%s\n' 'old-fde-only-check=REJECTS_VALID_ARM' 'native-ehabi-coverage=PASS' \
    'absent-index=REJECTED' 'truncated-index=REJECTED' 'missing-coverage=REJECTED' \
    'compact-refuse=REJECTED' \
    'original-inputs=UNCHANGED' > "$work/result.txt"
echo "arm-ehabi-regression=PASS results=$work"
