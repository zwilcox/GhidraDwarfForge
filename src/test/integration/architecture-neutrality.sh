#!/usr/bin/env bash
set -euo pipefail

repository_dir=$(realpath "$(dirname "$0")/../../..")
cd "$repository_dir"

# Architecture names, register spellings, and ELF machine selection belong in
# the target-description/register-map boundary, not in generic export code.
pattern='\b(x86_64|aarch64|arm32|mips32|mipsel|em_x86_64|em_aarch64|'
pattern+='em_arm|em_mips|rax|rbp|rsp|rdi|rsi|sp|lr|pc|'
pattern+='x([0-9]|[12][0-9]|30)|w([0-9]|[12][0-9]|30)|'
pattern+='r([0-9]|[12][0-9]|3[01]))\b'
if violations=$(rg -ni "$pattern" src/main/java \
        --glob '!**/DwarfTarget.java' \
        --glob '!**/TargetRegisterMap.java' \
        --glob '!**/PackagedNativeLibraries.java'); then
    echo "architecture-specific target logic escaped its audited boundary:" >&2
    echo "$violations" >&2
    exit 1
fi

echo "architecture-specific-files=ghidradwarfforge/nativeapi/DwarfTarget.java,ghidradwarfforge/locations/TargetRegisterMap.java"
echo "architecture-neutrality=PASS"
