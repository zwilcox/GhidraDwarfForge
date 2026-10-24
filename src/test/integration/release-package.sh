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

mkdir -p "$work/base/GhidraDwarfForge/support" \
    "$work/base/GhidraDwarfForge/third_party" \
    "$work/linux/compliance/libdwarf/licenses" \
    "$work/linux/compliance/libdwarf/patches" \
    "$work/linux/compliance/libdwarf/source" \
    "$work/windows/compliance/windows-runtime/zlib/licenses" \
    "$work/windows/compliance/windows-runtime/zstd/licenses"
printf 'name=GhidraDwarfForge\nversion=12.0.3\n' \
    > "$work/base/GhidraDwarfForge/extension.properties"
printf 'third-party notices\n' > "$work/base/GhidraDwarfForge/THIRD_PARTY_NOTICES.md"
printf 'corresponding source instructions\n' \
    > "$work/base/GhidraDwarfForge/third_party/CORRESPONDING_SOURCE.md"
printf '#!/usr/bin/env bash\n' > "$work/base/GhidraDwarfForge/support/wrapper"
chmod 755 "$work/base/GhidraDwarfForge/support/wrapper"
(
    cd "$work/base"
    find GhidraDwarfForge -print | LC_ALL=C sort | zip -X -q "$work/base.zip" -@
)
printf consumer > "$work/linux/libdwarf.so.2.3.2"
printf dependency > "$work/linux/libdwarf.so.2"
printf producer > "$work/linux/libdwarfp.so.2.3.2"
patch_hash=$(sha256sum < "$repository_dir/native/libdwarf/patches/0001-preserve-aarch64-relocation-type.patch")
patch_hash=${patch_hash%% *}
printf 'source patch SHA-256:\n%s  /fixture/patch.patch\n' "$patch_hash" \
    > "$work/linux/BUILD-METADATA.txt"
printf consumer > "$work/windows/libdwarf-2.dll"
printf producer > "$work/windows/libdwarfp-2.dll"
printf compression > "$work/windows/zlib1.dll"
printf compression > "$work/windows/libzstd.dll"
# GNU sha256sum escapes Windows backslashes and prefixes such records with '\'.
printf 'source patch SHA-256:\r\n\\%s *D:\\\\fixture\\\\patch.patch\r\n' "$patch_hash" \
    > "$work/windows/BUILD-METADATA.txt"
printf 'upstream copying\n' \
    > "$work/linux/compliance/libdwarf/licenses/UPSTREAM-COPYING"
printf 'lgpl text\n' > "$work/linux/compliance/libdwarf/licenses/LGPL-2.1.txt"
printf 'copyright\n' \
    > "$work/linux/compliance/libdwarf/licenses/LIBDWARFCOPYRIGHT"
printf 'producer copying\n' \
    > "$work/linux/compliance/libdwarf/licenses/LIBDWARFP-COPYING"
cp "$repository_dir/native/libdwarf/patches/0001-preserve-aarch64-relocation-type.patch" \
    "$work/linux/compliance/libdwarf/patches/0001-preserve-aarch64-relocation-type.patch"
printf 'source archive\n' \
    > "$work/linux/compliance/libdwarf/source/libdwarf-2.3.2.tar.xz"
(
    cd "$work/linux/compliance/libdwarf"
    find . -type f ! -name SOURCE-SHA256SUMS -print0 |
        LC_ALL=C sort -z | xargs -0 sha256sum \
        > SOURCE-SHA256SUMS
)
printf 'mingw-w64-x86_64-zlib 1.3.1-1\nmingw-w64-x86_64-zstd 1.5.7-1\n' \
    > "$work/windows/compliance/windows-runtime/PACKAGE-VERSIONS.txt"
printf 'zlib license\n' \
    > "$work/windows/compliance/windows-runtime/zlib/licenses/LICENSE"
printf 'zstd license\n' \
    > "$work/windows/compliance/windows-runtime/zstd/licenses/LICENSE"
(
    cd "$work/windows/compliance/windows-runtime"
    find . -type f ! -name RUNTIME-SHA256SUMS -print0 |
        LC_ALL=C sort -z | xargs -0 sha256sum \
        > RUNTIME-SHA256SUMS
)

mkdir -p "$work/windows-without-notices"
cp "$work/windows"/*.dll "$work/windows/BUILD-METADATA.txt" \
    "$work/windows-without-notices/"
if "$assembler" "$work/base.zip" "$work/linux" \
        "$work/windows-without-notices" "$work/incomplete.zip" \
        > "$work/incomplete.log" 2>&1; then
    echo "release assembly accepted missing Windows runtime notices" >&2
    exit 1
fi
grep -Fq 'required third-party compliance file is missing' "$work/incomplete.log"

cp -R "$work/windows" "$work/windows-with-unknown-runtime"
printf runtime > "$work/windows-with-unknown-runtime/libunreviewed.dll"
if "$assembler" "$work/base.zip" "$work/linux" \
        "$work/windows-with-unknown-runtime" "$work/unreviewed.zip" \
        > "$work/unreviewed.log" 2>&1; then
    echo "release assembly accepted an unreviewed Windows runtime" >&2
    exit 1
fi
grep -Fq 'bundled DLL has no reviewed notice policy' "$work/unreviewed.log"

printf 'previous release must survive rejection\n' > "$work/previous-release.zip"
reject_patch_metadata() {
    local name=$1 linux=$2 windows=$3 diagnostic=$4
    local base=${5:-"$work/base.zip"}
    cp "$work/previous-release.zip" "$work/$name.zip"
    if "$assembler" "$base" "$linux" "$windows" "$work/$name.zip" \
            > "$work/$name.log" 2>&1; then
        echo "release assembly accepted invalid patch provenance: $name" >&2
        exit 1
    fi
    grep -Fq "$diagnostic" "$work/$name.log"
    cmp "$work/previous-release.zip" "$work/$name.zip"
}

cp -R "$work/windows" "$work/windows-crlf-patch"
printf 'source patch SHA-256:\n%s  /fixture/patch.patch\n' \
    733405d03e2fd34f7bba971e6bbfe534d72ee9b3c1856879a7652f4eff17bc2a \
    > "$work/windows-crlf-patch/BUILD-METADATA.txt"
reject_patch_metadata windows-crlf-patch "$work/linux" "$work/windows-crlf-patch" \
    'win_x86_64 patch SHA-256 does not match bundled corresponding source'

for invalid in missing malformed duplicate mismatch; do
    candidate="$work/linux-$invalid-patch"
    cp -R "$work/linux" "$candidate"
    case "$invalid" in
        missing) printf 'metadata without patch identity\n' > "$candidate/BUILD-METADATA.txt" ;;
        malformed) printf 'source patch SHA-256:\nnot-a-checksum\n' > "$candidate/BUILD-METADATA.txt" ;;
        duplicate) cat "$work/linux/BUILD-METADATA.txt" >> "$candidate/BUILD-METADATA.txt" ;;
        mismatch)
            printf 'source patch SHA-256:\n%064d  /fixture/patch.patch\n' 0 \
                > "$candidate/BUILD-METADATA.txt"
            ;;
    esac
    diagnostic='invalid source patch SHA-256 record'
    if [[ $invalid == mismatch ]]; then
        diagnostic='linux_x86_64 patch SHA-256 does not match bundled corresponding source'
    fi
    reject_patch_metadata "linux-$invalid-patch" "$candidate" "$work/windows" "$diagnostic"
done

cp -R "$work/linux" "$work/linux-unpinned-patch"
printf '\n' >> "$work/linux-unpinned-patch/compliance/libdwarf/patches/0001-preserve-aarch64-relocation-type.patch"
(
    cd "$work/linux-unpinned-patch/compliance/libdwarf"
    find . -type f ! -name SOURCE-SHA256SUMS -print0 |
        LC_ALL=C sort -z | xargs -0 sha256sum > SOURCE-SHA256SUMS
)
reject_patch_metadata unpinned-patch "$work/linux-unpinned-patch" "$work/windows" \
    'bundled corresponding-source patch does not match the pinned SHA-256'

for invalid in absent empty symlink; do
    candidate="$work/linux-$invalid-file"
    cp -R "$work/linux" "$candidate"
    rm "$candidate/BUILD-METADATA.txt"
    case "$invalid" in
        empty) : > "$candidate/BUILD-METADATA.txt" ;;
        symlink) ln -s "$work/linux/BUILD-METADATA.txt" "$candidate/BUILD-METADATA.txt" ;;
    esac
    reject_patch_metadata "metadata-$invalid-file" "$candidate" "$work/windows" \
        'linux_x86_64 native input requires its own nonempty regular BUILD-METADATA.txt'
done

for inherited in os third_party/libdwarf third_party/windows-runtime; do
    name=${inherited//\//-}
    candidate="$work/base-with-$name"
    cp -R "$work/base" "$candidate"
    mkdir -p "$candidate/GhidraDwarfForge/$inherited"
    linux="$work/linux"
    case "$inherited" in
        os)
            mkdir -p "$candidate/GhidraDwarfForge/os/linux_x86_64"
            cp "$work/linux/BUILD-METADATA.txt" \
                "$candidate/GhidraDwarfForge/os/linux_x86_64/BUILD-METADATA.txt"
            linux="$work/linux-absent-file"
            ;;
        third_party/libdwarf)
            cp -R "$work/linux/compliance/libdwarf/." \
                "$candidate/GhidraDwarfForge/$inherited/"
            linux="$work/linux-unpinned-patch"
            ;;
        third_party/windows-runtime)
            cp -R "$work/windows/compliance/windows-runtime/." \
                "$candidate/GhidraDwarfForge/$inherited/"
            ;;
    esac
    (
        cd "$candidate"
        find GhidraDwarfForge -print | LC_ALL=C sort | zip -X -q "$work/base-with-$name.zip" -@
    )
    reject_patch_metadata "inherited-$name" "$linux" "$work/windows" \
        "base ZIP already contains $inherited" "$work/base-with-$name.zip"
done

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
test -s "$module/THIRD_PARTY_NOTICES.md"
test -s "$module/third_party/CORRESPONDING_SOURCE.md"
test -s "$module/third_party/libdwarf/licenses/LGPL-2.1.txt"
test -s "$module/third_party/libdwarf/source/libdwarf-2.3.2.tar.xz"
test -s "$module/third_party/windows-runtime/zlib/licenses/LICENSE"
test -s "$module/third_party/windows-runtime/zstd/licenses/LICENSE"
test ! -e "$module/os/linux_x86_64/compliance"
test ! -e "$module/os/win_x86_64/compliance"
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
