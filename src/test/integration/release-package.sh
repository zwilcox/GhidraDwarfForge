#!/usr/bin/env bash
set -euo pipefail

repository_dir=$(realpath "$(dirname "$0")/../../..")
assembler="$repository_dir/support/assemble-release.sh"
work=$(mktemp -d -t ghidra-dwarf-forge-release-test.XXXXXXXX)

cleanup() {
    case "$work" in
        /tmp/ghidra-dwarf-forge-release-test.*) rm -rf -- "$work" ;;
        *) echo "refusing to remove unexpected test path: $work" >&2 ;;
    esac
}
trap cleanup EXIT

mkdir -p "$work/base/GhidraDwarfForge/support" "$work/linux" "$work/windows"
printf 'name=GhidraDwarfForge\nversion=12.0.3\n' \
    > "$work/base/GhidraDwarfForge/extension.properties"
printf '#!/usr/bin/env bash\n' > "$work/base/GhidraDwarfForge/support/wrapper"
chmod 755 "$work/base/GhidraDwarfForge/support/wrapper"
(
    cd "$work/base"
    find GhidraDwarfForge -print | LC_ALL=C sort | zip -X -q "$work/base.zip" -@
)
printf consumer > "$work/linux/libdwarf.so.2.3.2"
printf dependency > "$work/linux/libdwarf.so.2"
printf producer > "$work/linux/libdwarfp.so.2.3.2"
printf 'linux metadata\n' > "$work/linux/BUILD-METADATA.txt"
printf consumer > "$work/windows/libdwarf-2.dll"
printf producer > "$work/windows/libdwarfp-2.dll"
printf runtime > "$work/windows/libwinpthread-1.dll"
printf 'windows metadata\n' > "$work/windows/BUILD-METADATA.txt"

"$assembler" "$work/base.zip" "$work/linux" "$work/windows" "$work/first.zip"
"$assembler" "$work/base.zip" "$work/linux" "$work/windows" "$work/second.zip"
cmp "$work/first.zip" "$work/second.zip"
unzip -q "$work/first.zip" -d "$work/unpacked"
module="$work/unpacked/GhidraDwarfForge"
(
    cd "$module"
    sha256sum -c RELEASE-SHA256SUMS
    cd os/linux_x86_64
    sha256sum -c SHA256SUMS
    cd ../win_x86_64
    sha256sum -c SHA256SUMS
)
grep -Fxq 'consumer=libdwarf.so.2.3.2' \
    "$module/os/linux_x86_64/NATIVE-PAIR.properties"
grep -Fxq 'producer=libdwarfp-2.dll' \
    "$module/os/win_x86_64/NATIVE-PAIR.properties"
zipinfo -l "$work/first.zip" | grep -Eq \
    '^-rwxr-xr-x.*GhidraDwarfForge/support/wrapper$'
if zipinfo -T "$work/first.zip" | awk \
        '/GhidraDwarfForge/ && $0 !~ /19800201[.]000000/ { failed = 1 } END { exit failed }'; then
    :
else
    echo "release ZIP contains a non-normalized timestamp" >&2
    exit 1
fi

echo release-package=PASS
