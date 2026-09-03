# Third-party notices

GhidraDwarfForge is licensed under the MIT License in `LICENSE`. That license
applies to project-authored work. The dependencies listed below retain their
upstream licenses.

## Components included in the release bundle

### libdwarf and libdwarfp

- Version: 2.3.2
- Source commit: `af7b278c6aa2ae9daad94fb7f8bffdc0e9980993`
- Upstream: <https://github.com/davea42/libdwarf-code>
- License: primarily GNU Lesser General Public License version 2.1, with
  two-clause/three-clause BSD and public-domain files identified by upstream

The Linux and Windows release directories contain dynamically linked
`libdwarf` and `libdwarfp` libraries. Their upstream notices and complete
license text are under `third_party/libdwarf/licenses/` in the release bundle.
The exact corresponding source archive, the GhidraDwarfForge patch applied to
it, and reconstruction instructions are provided as described in
`third_party/CORRESPONDING_SOURCE.md`.

GhidraDwarfForge loads these libraries through JNA. Users may run compatible
modified builds instead of the packaged copies by supplying the explicit
`--libdwarf` and `--libdwarfp` options, or the corresponding PowerShell
options.

### zlib and Zstandard

The Windows release includes `zlib1.dll` and `libzstd.dll` because the MinGW
libdwarf build dynamically depends on them. The exact MSYS2 package versions
used by each build and their upstream license texts are under
`third_party/windows-runtime/` in the release bundle.

- zlib upstream: <https://zlib.net/>
- Zstandard upstream: <https://github.com/facebook/zstd>

## Host-provided dependencies not included in the release bundle

### Ghidra

Ghidra 12.0.3 is required to build and run this extension but is not
redistributed by GhidraDwarfForge. Ghidra is licensed under the Apache License
2.0: <https://github.com/NationalSecurityAgency/ghidra>.

### Java Native Access

GhidraDwarfForge uses the JNA 5.14.0 classes supplied by Ghidra 12.0.3 and does
not bundle a private JNA copy. JNA is dual-licensed under Apache License 2.0 or
LGPL 2.1-or-later: <https://github.com/java-native-access/jna>.
