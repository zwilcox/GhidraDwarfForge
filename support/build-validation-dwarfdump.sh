#!/usr/bin/env bash
# Build the independent test consumer; this executable is never a release native.
set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "usage: $0 <libdwarf-2.3.2.tar.xz> <new-output-directory> <result-directory>" >&2
    exit 64
fi
archive=$(realpath "$1")
output=$(realpath -m "$2")
results=$(realpath -m "$3")
support_dir=$(realpath "$(dirname "$0")")
checker_patch="$support_dir/validation/0001-check-line-sequences.patch"
reader_patch="$support_dir/validation/0002-accept-bounded-extended-program-count.patch"
diagnostic_patch="$support_dir/validation/0003-preserve-bounded-harmless-diagnostics.patch"
calling_patch="$support_dir/validation/0004-recognize-subroutine-calling-convention.patch"
terminator_patch="$support_dir/validation/0005-honor-eh-frame-zero-terminator.patch"
locviews_patch="$support_dir/validation/0006-locviews-are-not-die-references.patch"
bounds_patch="$support_dir/validation/0007-preserve-low-elf-address-bounds.patch"
bounds_patch_hash=f4a81a948702b20e105e2a646eb08e747264e9b028949da287580458fb29360d
locviews_patch_hash=54fce0dd7b7f19775cfb2bf95f610a4c3f4b96dd98d28ce99580d30c4e6aa879
terminator_patch_hash=d69033dbf8b67380c06b51932018c2c024e5610f3e5343cd75915e206ac16b08
launcher="$support_dir/validation/run-dwarfdump.sh"
calling_patch_hash=a1b5cc6d63795aeda62b5945bf8991360882c7334003e9912e274638ec073581
configuration_hash=842bba9230de82059dfcef1485114cf3c33eae8be2973c649d176f4ad18972ef
source_hash=7992e7b9019ebfabdda5773e86243517c48cf89fafed3209e853692bc9573efd
patch_hash=69340f63ee78c06309731a40bb1e0e9e193b5d2f659e5f050ef413138649f696
reader_patch_hash=8468426396e6a28f755077681eec78d326744a535c7aade9d17d9a1acef73b46
diagnostic_patch_hash=e9f7eb0e613b4a4e859377ad12563ad514d24f7ee81b04378a30b8e99e403139
if [[ -e "$output" || -L "$output" ]]; then
    echo "validation-tool output already exists: $output" >&2
    exit 1
fi
printf '%s  %s\n' "$source_hash" "$archive" | sha256sum -c -
printf '%s  %s\n' "$patch_hash" "$checker_patch" | sha256sum -c -
printf '%s  %s\n' "$reader_patch_hash" "$reader_patch" | sha256sum -c -
printf '%s  %s\n' "$diagnostic_patch_hash" "$diagnostic_patch" | sha256sum -c -
printf '%s  %s\n' "$calling_patch_hash" "$calling_patch" | sha256sum -c -
printf '%s  %s\n' "$terminator_patch_hash" "$terminator_patch" | sha256sum -c -
printf '%s  %s\n' "$locviews_patch_hash" "$locviews_patch" | sha256sum -c -
printf '%s  %s\n' "$bounds_patch_hash" "$bounds_patch" | sha256sum -c -
mkdir -p "$results" "$(dirname "$output")"
work=$(mktemp -d "$results/build.XXXXXXXX")
printf 'validation-tool-build=%s\n' "$work"
tar -xf "$archive" -C "$work"
source="$work/libdwarf-2.3.2"
(
    cd "$source"
    patch -p1 < "$checker_patch" > "$work/patch.log" 2>&1
    patch -p1 < "$reader_patch" > "$work/reader-patch.log" 2>&1
    patch -p1 < "$diagnostic_patch" > "$work/diagnostic-patch.log" 2>&1
    patch -p1 < "$calling_patch" > "$work/calling-patch.log" 2>&1
    patch -p1 < "$terminator_patch" > "$work/terminator-patch.log" 2>&1
    patch -p1 < "$locviews_patch" > "$work/locviews-patch.log" 2>&1
    patch -p1 < "$bounds_patch" > "$work/bounds-patch.log" 2>&1
    ./configure --enable-static --disable-shared --disable-dwarfgen \
        > "$work/configure.log" 2>&1
    make -j"${FORGE_BUILD_JOBS:-$(nproc)}" > "$work/make.log" 2>&1
)
stage="$work/output"
mkdir -p "$stage/bin" "$stage/libexec" "$stage/share/dwarfdump" \
    "$stage/source/support/validation" "$stage/licenses"
printf '%s  %s\n' "$configuration_hash" "$source/src/bin/dwarfdump/dwarfdump.conf" | sha256sum -c -
cp "$source/src/bin/dwarfdump/dwarfdump" "$stage/libexec/"
cp "$source/src/bin/dwarfdump/dwarfdump.conf" "$stage/share/dwarfdump/"
cp "$launcher" "$stage/bin/dwarfdump"
chmod 755 "$stage/bin/dwarfdump" "$stage/libexec/dwarfdump"
cp "$archive" "$stage/source/libdwarf-2.3.2.tar.xz"
cp "$0" "$stage/source/support/build-validation-dwarfdump.sh"
cp "$checker_patch" "$stage/source/support/validation/"
cp "$reader_patch" "$stage/source/support/validation/"
cp "$diagnostic_patch" "$stage/source/support/validation/"
cp "$calling_patch" "$stage/source/support/validation/"
cp "$terminator_patch" "$stage/source/support/validation/"
cp "$locviews_patch" "$stage/source/support/validation/"
cp "$bounds_patch" "$stage/source/support/validation/"
cp "$launcher" "$stage/source/support/validation/"
cp "$support_dir/validation/README.md" "$stage/source/support/validation/"
cp "$support_dir/../LICENSE" "$stage/source/LICENSE"
cp "$source/COPYING" "$stage/licenses/UPSTREAM-COPYING"
cp "$source/src/lib/libdwarf/LGPL.txt" "$stage/licenses/LGPL-2.1.txt"
cp "$source/src/lib/libdwarf/LIBDWARFCOPYRIGHT" "$stage/licenses/"
cp "$source/src/bin/dwarfdump/COPYING" "$stage/licenses/DWARFDUMP-COPYING"
cp "$source/src/bin/dwarfdump/GPL.txt" "$stage/licenses/DWARFDUMP-GPL.txt"
cp "$source/src/bin/dwarfdump/DWARFDUMPCOPYRIGHT" "$stage/licenses/"
readelf -d "$stage/libexec/dwarfdump" > "$work/dependencies.txt"
if grep -Eq 'NEEDED.*libdwarf' "$work/dependencies.txt"; then
    echo 'validation executable unexpectedly requires a shared libdwarf' >&2
    exit 1
fi
"$stage/bin/dwarfdump" --version > "$work/version.txt"
grep -Fq '2.3.2' "$work/version.txt"
{
    printf '%s\n' 'purpose=validation-only; excluded from release native inputs' \
        'libdwarf-release=v2.3.2' \
        'source-commit=af7b278c6aa2ae9daad94fb7f8bffdc0e9980993' \
        "source-archive-sha256=$source_hash" \
        "validation-checker-patch-sha256=$patch_hash" \
        "validation-reader-patch-sha256=$reader_patch_hash" \
        "validation-diagnostic-patch-sha256=$diagnostic_patch_hash" \
        "validation-calling-convention-patch-sha256=$calling_patch_hash" \
        "validation-terminator-patch-sha256=$terminator_patch_hash" \
        "validation-locviews-patch-sha256=$locviews_patch_hash" \
        "validation-bounds-patch-sha256=$bounds_patch_hash" \
        "validation-configuration-sha256=$configuration_hash" \
        'entry-point=bin/dwarfdump; executable=libexec/dwarfdump' \
        'configure=--enable-static --disable-shared --disable-dwarfgen' \
        'producer-patch=not-applied'
    cat "$work/version.txt"
    cc --version
    cat "$work/dependencies.txt"
} > "$stage/BUILD-METADATA.txt"
cat > "$stage/CORRESPONDING_SOURCE.md" <<'EOF'
This validation-only executable is built from the included libdwarf 2.3.2
archive and seven explicitly identified validation-only patches: the dwarfdump
line-sequence correction and bounded PN_XNUM recognition in its static ELF
consumer, plus complete harmless-diagnostic evidence up to 65536 messages with
checked allocation and explicit rejection above that bound. The fourth recognizes
the LLVM/GDB function-pointer calling-convention extension in the existing
tag/attribute extension table; all other combinations and checks remain active.
The fifth recognizes GNU four-byte .eh_frame terminators before the legacy IRIX
eight-byte length heuristic; malformed prefixes and .debug_frame stay checked.
The sixth keeps GNU location-view section offsets out of DIE-reference traversal;
actual DIE references and all other check categories remain enabled.
The seventh derives ELF address bounds from nonempty allocated sections without
an invented first-page exclusion; address checks remain enabled.
This executable and all seven patches are excluded from GhidraDwarfForge release-native inputs;
shipped consumer/producer library sources are unchanged.
The relocatable bin/dwarfdump launcher checks the pinned upstream configuration
and selects it explicitly with --file-name, without consulting host defaults.
The ELF executable is libexec/dwarfdump; configuration is under share/dwarfdump.
Both executable and launcher/configuration are covered by SHA256SUMS.
Licenses are in licenses/ and the complete upstream source archive; the
repository build helper is MIT licensed.

On Ubuntu 24.04, install build-essential, zlib1g-dev, libzstd-dev, binutils,
patch and xz-utils. From source/, reproduce with:

    bash support/build-validation-dwarfdump.sh libdwarf-2.3.2.tar.xz NEW_OUTPUT RESULTS

NEW_OUTPUT must not exist. The source/patch checksums, configure options,
compiler, tool version and dynamic dependencies are recorded in BUILD-METADATA.txt.
EOF
(
    cd "$stage"
    find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > "$work/SHA256SUMS"
)
mv "$work/SHA256SUMS" "$stage/"
mv "$stage" "$output"
printf 'validation-tool=%s/bin/dwarfdump\n' "$output"
