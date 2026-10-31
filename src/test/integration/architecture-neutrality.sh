#!/usr/bin/env bash
set -euo pipefail

repository_dir=$(realpath "$(dirname "$0")/../../..")
python3 - "$repository_dir" <<'PYTHON'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
source = root / "src/main/java"
# Register/target descriptions and typed ELF metadata readers are the audited
# architecture-specific boundary. Keep exact paths, not basename exceptions.
audited = {
    "ghidradwarfforge/nativeapi/DwarfTarget.java",
    "ghidradwarfforge/locations/TargetRegisterMap.java",
    "ghidradwarfforge/GhidraArm32FunctionModes.java",
    "ghidradwarfforge/elf/Arm32ModeSymbols.java",
    "ghidradwarfforge/elf/MipsAbiFlags.java",
    "ghidradwarfforge/elf/MipsFunctionAliasSymbols.java",
    "ghidradwarfforge/nativeapi/PackagedNativeLibraries.java",
}
pattern = re.compile(r"\b(i386|x86|x86_32|em_386|eax|ecx|edx|ebx|esp|ebp|esi|edi|eip|eflags|x86_64|aarch64|arm32|mips32|mipsel|em_x86_64|em_aarch64|"
    r"em_arm|em_mips|thumb|tmode|rax|rbp|rsp|rdi|rsi|sp|lr|pc|"
    r"x([0-9]|[12][0-9]|30)|w([0-9]|[12][0-9]|30)|"
    r"r([0-9]|[12][0-9]|3[01]))\b", re.IGNORECASE)
files = sorted(source.rglob("*.java"))
if not files:
    raise SystemExit("architecture check found no Java sources")
violations = []
for path in files:
    if path.relative_to(source).as_posix() in audited:
        continue
    for line, text in enumerate(path.read_text().splitlines(), 1):
        if pattern.search(text):
            violations.append(f"{path.relative_to(root)}:{line}:{text}")
if violations:
    print("architecture-specific target logic escaped its audited boundary:", file=sys.stderr)
    print("\n".join(violations), file=sys.stderr)
    raise SystemExit(1)
print("architecture-specific-files=" + ",".join(sorted(audited)))
print("architecture-neutrality=PASS")
PYTHON
