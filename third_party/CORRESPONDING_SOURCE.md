# Corresponding source for bundled libdwarf libraries

Every native-inclusive GhidraDwarfForge release contains the complete source
inputs used to build its bundled LGPL libdwarf and libdwarfp libraries:

```text
third_party/libdwarf/source/libdwarf-2.3.2.tar.xz
third_party/libdwarf/patches/0001-preserve-aarch64-relocation-type.patch
```

The source archive is the official libdwarf v2.3.2 release archive. Its
SHA-256 is:

```text
7992e7b9019ebfabdda5773e86243517c48cf89fafed3209e853692bc9573efd
```

It corresponds to source commit
`af7b278c6aa2ae9daad94fb7f8bffdc0e9980993`. The release's
`RELEASE-SHA256SUMS` also covers the archive, patch, notices, and every bundled
native library.

## Reconstructing the libraries

Extract and patch the included source:

```bash
tar -xf libdwarf-2.3.2.tar.xz
cd libdwarf-2.3.2
patch -p1 < ../0001-preserve-aarch64-relocation-type.patch
```

The production configuration is:

```bash
./configure --enable-shared --enable-dwarfgen --disable-static \
    --prefix="$PWD/install"
make -j"$(nproc)"
```

The Linux build then runs `make install` and applies an `$ORIGIN` RUNPATH to
`libdwarfp.so.2.3.2`. The Windows build uses an MSYS2 MINGW64 shell and copies
the built `libdwarf-2.dll` and `libdwarfp-2.dll` together with their non-system
runtime dependencies. Exact compilers, package versions, native hashes, and
dependency names are recorded in each platform's `BUILD-METADATA.txt`.

The included patch is also maintained in the GhidraDwarfForge source
repository at `native/libdwarf/patches/`. No generated or undisclosed source
changes are applied by the release workflow.

## Using a modified build

The extension's headless wrappers normally select the packaged library pair.
Compatible modified libraries can be supplied instead with the paired
`--libdwarf=/path/to/libdwarf` and `--libdwarfp=/path/to/libdwarfp` options.
PowerShell uses the equivalent `-Libdwarf` and `-Libdwarfp` options. Both paths
must be supplied together.
