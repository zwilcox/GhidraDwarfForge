#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
    echo "usage: $0 <base-extension.zip> <linux-native-dir> <windows-native-dir> <output.zip>" >&2
    exit 64
fi

base_archive=$(realpath "$1")
linux_input=$(realpath "$2")
windows_input=$(realpath "$3")
output_parent=$(realpath "$(dirname "$4")")
output="$output_parent/$(basename "$4")"
repository_dir=$(realpath "$(dirname "$0")/..")
release_version=$(tr -d '\r\n' < "$repository_dir/VERSION")

[[ "$release_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]] || {
    echo "invalid semantic version in VERSION: $release_version" >&2
    exit 1
}
[[ -f "$base_archive" ]] || { echo "base extension ZIP is missing" >&2; exit 1; }
[[ -d "$linux_input" ]] || { echo "Linux native directory is missing" >&2; exit 1; }
[[ -d "$windows_input" ]] || { echo "Windows native directory is missing" >&2; exit 1; }

temporary_root=$(mktemp -d -t ghidra-dwarf-forge-release.XXXXXXXX)
cleanup() {
    case "$temporary_root" in
        /tmp/ghidra-dwarf-forge-release.*|"${RUNNER_TEMP:-/nonexistent}"/ghidra-dwarf-forge-release.*)
            rm -rf -- "$temporary_root"
            ;;
        *)
            echo "refusing to remove unexpected temporary path: $temporary_root" >&2
            ;;
    esac
}
trap cleanup EXIT

stage="$temporary_root/stage"
mkdir -p "$stage"
unzip -q "$base_archive" -d "$stage"
module="$stage/GhidraDwarfForge"
[[ -f "$module/extension.properties" ]] || {
    echo "base ZIP does not contain GhidraDwarfForge/extension.properties" >&2
    exit 1
}

copy_platform() {
    local platform=$1 input=$2 consumer_pattern=$3 producer_pattern=$4
    local destination="$module/os/$platform"
    mkdir -p "$destination"
    find "$input" -maxdepth 1 -type f ! -name 'SHA256SUMS' -exec cp {} "$destination/" \;

    local consumers=() producers=()
    mapfile -t consumers < <(find "$destination" -maxdepth 1 -type f \
        -name "$consumer_pattern" ! -name 'libdwarfp*' -printf '%f\n' | LC_ALL=C sort)
    mapfile -t producers < <(find "$destination" -maxdepth 1 -type f \
        -name "$producer_pattern" -printf '%f\n' | LC_ALL=C sort)
    if [[ ${#consumers[@]} -ne 1 || ${#producers[@]} -ne 1 ]]; then
        echo "$platform requires exactly one versioned consumer and producer" >&2
        exit 1
    fi
    {
        echo "consumer=${consumers[0]}"
        echo "producer=${producers[0]}"
    } > "$destination/NATIVE-PAIR.properties"
    (
        cd "$destination"
        find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%P\0' |
            LC_ALL=C sort -z | xargs -0 sha256sum > SHA256SUMS
    )
}

copy_platform linux_x86_64 "$linux_input" 'libdwarf.so.2.3.2' 'libdwarfp.so.2.3.2'
copy_platform win_x86_64 "$windows_input" 'libdwarf-*.dll' 'libdwarfp-*.dll'

{
    echo "release-version=$release_version"
    echo "ghidra-version=12.0.3"
    echo "libdwarf-release=v2.3.2"
    echo "libdwarf-source-commit=af7b278c6aa2ae9daad94fb7f8bffdc0e9980993"
    echo "libdwarf-archive-sha256=7992e7b9019ebfabdda5773e86243517c48cf89fafed3209e853692bc9573efd"
    echo "host-platforms=linux_x86_64,win_x86_64"
} > "$module/RELEASE-MANIFEST.txt"

(
    cd "$module"
    find . -type f ! -name RELEASE-SHA256SUMS -printf '%P\0' |
        LC_ALL=C sort -z | xargs -0 sha256sum > RELEASE-SHA256SUMS
)

find "$stage" -exec touch -h -t 198002010000.00 {} +
temporary_archive="$temporary_root/release.zip"
(
    cd "$stage"
    find GhidraDwarfForge -print | LC_ALL=C sort | zip -X -q "$temporary_archive" -@
)
unzip -tq "$temporary_archive" >/dev/null
mv "$temporary_archive" "$output"
sha256sum "$output"
