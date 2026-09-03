# libdwarf native provenance

Production native builds are pinned to the official libdwarf 2.3.2 release.

| Field | Value |
|---|---|
| Upstream repository | `https://github.com/davea42/libdwarf-code` |
| Release tag | `v2.3.2` |
| Tag object | `33357037b0b80238ef635a65f2f6c77d2c1925f7` |
| Source commit | `af7b278c6aa2ae9daad94fb7f8bffdc0e9980993` |
| Release archive | `libdwarf-2.3.2.tar.xz` |
| Archive SHA-256 | `7992e7b9019ebfabdda5773e86243517c48cf89fafed3209e853692bc9573efd` |
| Upstream release date | 2026-07-07 |
| Local audit date | 2026-09-02 |

The checksum was verified against the digest published by GitHub for the
official release asset and independently recomputed after download.

The production configure flags are:

```text
--enable-shared --enable-dwarfgen --disable-static
```

Release builds retain the default decompression support and install zlib/zstd
development dependencies. A local ABI-audit build may use
`--disable-decompression` when those development packages are unavailable;
such a build must not be distributed as a production native.

The authoritative headers for the JNA audit are:

```text
src/lib/libdwarf/dwarf.h
src/lib/libdwarf/libdwarf.h
src/lib/libdwarfp/libdwarfp.h
```

At the pinned commit, `Dwarf_Unsigned`, `Dwarf_Signed`, `Dwarf_Off`, and
`Dwarf_Addr` are fixed 64-bit `long long` types. `Dwarf_Half` is 16-bit and
`Dwarf_Small` is 8-bit. `Dwarf_Error` and producer handles are opaque pointers.

The workflow uploads reviewed build artifacts. It does not automatically
commit opaque native binaries back to `main`.

The Windows CI build writes `BUILD-METADATA.txt` beside its DLL artifact with
the pinned release/commit, configure flags, compiler version, SHA-256 for every
bundled DLL, and each DLL's dependency names. Required consumer/producer
exports and recursively discovered non-system MinGW runtime DLLs are build
gates. This path is **PRESENT, UNVERIFIED** until a GitHub-hosted Windows run
passes; no Windows release-native hashes are claimed in advance.

## Local ABI smoke evidence

On 2026-09-02, a locally compiled Linux v2.3.2 pair passed the standalone Java
producer smoke test in four cross-target configurations: x86-64/ELF64 little
endian, AArch64/ELF64 little endian, and MIPS/ELF32 in both byte orders. Each
run validated target-address relocations plus producer section relocations.

The same native pair subsequently passed real headless symbol export and
native/QEMU GDB breakpoint tests for all four targets across ET_EXEC, PIE, and
no-section-table inputs. These are local audit-build results, not packaged
release-native or Windows evidence.

The locally built files had these hashes:

```text
libdwarf.so.2.3.2  752b38cb8641eb441d53ddf44e59397a4bf1caa60180d38005b9d5a0b81918cf
libdwarfp.so.2.3.2 c1e9a37488fc52deff3265a9683c66e39a66e38123b539318096ae23500f2252
```

These hashes identify the local ABI-audit build, which disabled decompression;
they are not release-native hashes.
