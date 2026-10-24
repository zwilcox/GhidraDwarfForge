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
pinned_patch_sha256=b98561b3e63b76546bd2f18d81d53e188b56deb637b5e145205b3b6eedadf696

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
[[ -f "$module/THIRD_PARTY_NOTICES.md" ]] || {
    echo "base ZIP does not contain GhidraDwarfForge/THIRD_PARTY_NOTICES.md" >&2
    exit 1
}
[[ -f "$module/third_party/CORRESPONDING_SOURCE.md" ]] || {
    echo "base ZIP does not contain corresponding-source instructions" >&2
    exit 1
}
for entry_point in GhidraDwarfForge.java ExportGhidraDwarfForge.java; do
    [[ -s "$module/ghidra_scripts/$entry_point" ]] || {
        echo "base ZIP is missing required script: $entry_point" >&2
        exit 1
    }
done

for bundled_directory in os third_party/libdwarf third_party/windows-runtime; do
    if [[ -e "$module/$bundled_directory" || -L "$module/$bundled_directory" ]]; then
        echo "base ZIP already contains $bundled_directory; supply the unbundled Gradle extension ZIP" >&2
        exit 1
    fi
done

copy_platform() {
    local platform=$1 input=$2 consumer_pattern=$3 producer_pattern=$4
    local destination="$module/os/$platform"
    if [[ ! -f "$input/BUILD-METADATA.txt" || -L "$input/BUILD-METADATA.txt" ||
            ! -s "$input/BUILD-METADATA.txt" ]]; then
        echo "$platform native input requires its own nonempty regular BUILD-METADATA.txt" >&2
        exit 1
    fi
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
for bundled_dll in "$module/os/win_x86_64"/*.dll; do
    bundled_name=$(basename "$bundled_dll" | tr '[:upper:]' '[:lower:]')
    case "$bundled_name" in
        libdwarf-*.dll|libdwarfp-*.dll|libzstd.dll|zlib1.dll) ;;
        *)
            echo "bundled DLL has no reviewed notice policy: $bundled_name" >&2
            exit 1
            ;;
    esac
done

libdwarf_compliance="$linux_input/compliance/libdwarf"
windows_runtime_compliance="$windows_input/compliance/windows-runtime"
required_compliance_files=(
    "$libdwarf_compliance/licenses/UPSTREAM-COPYING"
    "$libdwarf_compliance/licenses/LGPL-2.1.txt"
    "$libdwarf_compliance/licenses/LIBDWARFCOPYRIGHT"
    "$libdwarf_compliance/licenses/LIBDWARFP-COPYING"
    "$libdwarf_compliance/patches/0001-preserve-aarch64-relocation-type.patch"
    "$libdwarf_compliance/source/libdwarf-2.3.2.tar.xz"
    "$libdwarf_compliance/SOURCE-SHA256SUMS"
    "$windows_runtime_compliance/PACKAGE-VERSIONS.txt"
    "$windows_runtime_compliance/RUNTIME-SHA256SUMS"
    "$windows_runtime_compliance/zlib/licenses/LICENSE"
    "$windows_runtime_compliance/zstd/licenses/LICENSE"
)
for compliance_file in "${required_compliance_files[@]}"; do
    [[ -s "$compliance_file" ]] || {
        echo "required third-party compliance file is missing: $compliance_file" >&2
        exit 1
    }
done
mkdir -p "$module/third_party"
cp -R "$libdwarf_compliance" "$module/third_party/libdwarf"
cp -R "$windows_runtime_compliance" "$module/third_party/windows-runtime"
(
    cd "$module/third_party/libdwarf"
    sha256sum -c SOURCE-SHA256SUMS
)
(
    cd "$module/third_party/windows-runtime"
    sha256sum -c RUNTIME-SHA256SUMS
)

bundled_patch_sha256=$(sha256sum < \
    "$module/third_party/libdwarf/patches/0001-preserve-aarch64-relocation-type.patch")
bundled_patch_sha256=${bundled_patch_sha256%% *}
if [[ $bundled_patch_sha256 != "$pinned_patch_sha256" ]]; then
    echo 'bundled corresponding-source patch does not match the pinned SHA-256' >&2
    exit 1
fi
for platform in linux_x86_64 win_x86_64; do
    metadata="$module/os/$platform/BUILD-METADATA.txt"
    # GNU sha256sum prefixes a record with '\' when its filename is escaped.
    # Accept that encoding and CRLF metadata, but require the canonical hash.
    if ! recorded_patch_sha256=$(awk '
        {
            sub(/\r$/, "")
            if ($0 == "source patch SHA-256:") {
                records++
                if (getline <= 0) invalid = 1
                sub(/\r$/, "")
                sub(/^\\/, "")
                hash = substr($0, 1, 64)
                separator = substr($0, 65, 2)
                if (length(hash) != 64 || hash ~ /[^0-9a-f]/ || length($0) <= 66 ||
                        (separator != "  " && separator != " *")) invalid = 1
            }
        }
        END {
            if (records != 1 || invalid) exit 1
            print hash
        }
    ' "$metadata"); then
        echo "invalid source patch SHA-256 record in $platform BUILD-METADATA.txt" >&2
        exit 1
    fi
    if [[ $recorded_patch_sha256 != "$bundled_patch_sha256" ]]; then
        echo "$platform patch SHA-256 does not match bundled corresponding source" >&2
        exit 1
    fi
done

{
    echo "release-version=$release_version"
    echo "ghidra-version=12.0.3"
    echo "libdwarf-release=v2.3.2"
    echo "libdwarf-source-commit=af7b278c6aa2ae9daad94fb7f8bffdc0e9980993"
    echo "libdwarf-archive-sha256=7992e7b9019ebfabdda5773e86243517c48cf89fafed3209e853692bc9573efd"
    echo "libdwarf-patch-sha256=$pinned_patch_sha256"
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
