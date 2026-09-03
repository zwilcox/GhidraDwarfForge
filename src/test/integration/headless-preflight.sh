#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <ghidra-install-directory> [target ...]" >&2
    exit 2
fi

ghidra_dir=$(realpath "$1")
shift
if [[ $# -eq 0 ]]; then
    targets=(x86_64 aarch64 mips32be mips32le)
else
    targets=("$@")
fi
repository_dir=$(realpath "$(dirname "$0")/../../..")
fixture_dir="$repository_dir/build/fixtures"
result_dir="$repository_dir/build/test-results/headless-preflight"
temporary_projects=$(mktemp -d -t ghidra-dwarf-forge-headless.XXXXXXXX)
fixture_suffix=${FIXTURE_SUFFIX:-exec.stripped}

cleanup() {
    case "$temporary_projects" in
        /tmp/ghidra-dwarf-forge-headless.*)
            rm -rf -- "$temporary_projects"
            ;;
        *)
            echo "refusing to remove unexpected temporary path: $temporary_projects" >&2
            ;;
    esac
}
trap cleanup EXIT

mkdir -p "$result_dir"

for target in "${targets[@]}"; do
    fixture="$fixture_dir/$target/semantic.$fixture_suffix"
    log="$result_dir/$target.$fixture_suffix.log"
    if [[ ! -f "$fixture" ]]; then
        echo "missing fixture: $fixture; run make -C src/test/fixtures all" >&2
        exit 1
    fi

    "$ghidra_dir/support/analyzeHeadless" \
        "$temporary_projects" "GhidraDwarfForge_$target" \
        -deleteProject \
        -import "$fixture" \
        -analysisTimeoutPerFile 120 \
        -scriptPath "$repository_dir/ghidra_scripts" \
        -postScript GhidraDwarfForge.java 2>&1 | tee "$log"

    grep -q "GhidraDwarfForge preflight" "$log"
    grep -q "REPORT: Import succeeded" "$log"
done

echo "headless-preflight=PASS"
