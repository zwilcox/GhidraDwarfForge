# Optional GDB companion

**PRESENT, UNVERIFIED across the complete support matrix:** the exporter can
generate a deterministic `<sidecar>.gdb.py` with the matched sidecar and synthetic
source. Current local evidence and remaining acceptance are recorded in
[the completion ledger](DEBUG-LOADING-COMPLETION-PLAN.md). This is development
work for #107; it is not a claim that a published release contains this feature.

Enable generation with Bash `--gdb-loader`, PowerShell `-GdbLoader`, or the
Script Manager launcher `ExportGhidraDwarfForgeWithGdbLoader.java`. Direct
`GhidraDwarfForge.java` invocation accepts `--gdb-loader` together with its
ordinary native-library selection. The default export remains the existing
sidecar/source pair. The companion path and SHA-256 appear in the console;
the existing schema-1 report continues to describe the sidecar/source pair.

For a local executable:

```gdb
file /path/to/program
set auto-solib-add off
starti
source /path/to/program.dbg.gdb.py
forge-load
break recovered_function
continue
```

The `source` command consumes the remainder of its line as a filename; paths
containing spaces work without adding quotes to that command. Sourcing registers
commands and prints an identifier. It does not load symbols, run the target or
edit `.gdbinit`. If multiple companions are registered, use `forge-load --list`
and `forge-load IDENTIFIER`. `forge-unload IDENTIFIER` removes only the objfile
installed by that companion. Repeated sourcing/loading does not add duplicates.

The target must be stopped. For an attached process, source and load after
`attach PID`. For a library, stop after it is mapped before invoking its loader.
The runtime must expose the Python event and scoped-parameter APIs checked by
the companion; current local evidence uses GDB 15.1. Multiple-inferior sessions
are explicitly rejected rather than sharing possibly different relocations.

Automatic discovery currently parses Linux-style `info proc mappings` with
file offsets. Selection uses the full recorded target path, not a basename.
Use `--module EXACT_RUNTIME_PATH` when the runtime names a different path, such
as a remote target pathname or an executable associated with a verified backup.
It still must match the companion's code bytes at the selected address.

When a remote transport cannot provide mappings, supply an explicit load bias:

```gdb
forge-load IDENTIFIER --bias 0x12340000
```

Load bias means **runtime virtual address minus ELF link-time virtual address**.
It is not the runtime `.text` address or Ghidra's analysis image base. The loader
uses `add-symbol-file ... -o BIAS` to relocate all sections. The sidecar keeps
link-time addresses and can be reused across ASLR runs. No fixed ASLR base or
page size is assumed. An override selects among ambiguous module instances but
cannot override contradictory mapping evidence or failed identity checks.

Before loading, the helper streams and checks the selected executable, sidecar
and source hashes, target pointer width, and immutable executable bytes in
target memory. It also checks mapped ELF header identity when available. The
section-table fields permitted to change during a future debuglink attachment
are excluded from memory matching; the full selected file hash is still checked.
Changed code, text relocations, writable executable LOAD segments, unreadable
identity bytes, excess resource limits and unsupported mapping formats produce
diagnostics. They do not trigger guessed symbol addresses. Ordinary manual GDB
loading remains available independently of companion generation.

Exit, executable changes and library-unload observations invalidate loaded
symbols. The helper rechecks loaded mappings/code at stops; after invalidation,
invoke `forge-load` again with the current mapping or an explicit fresh bias.
An override is not carried automatically into a restarted target. An unrelated
manually loaded sidecar is not silently removed or adopted.

Paths are absolute and bound to the generated artifact generation. Regenerate
after moving or replacing those files. An old companion left after an ordinary
pair-only export rejects changed artifacts. Controls and CR/LF in paths are
rejected explicitly. Resource bounds are 4,096 mapping rows, 1,024 LOAD/check
records, 256 candidate instances, and 1 GiB of streamed identity ranges. These
are implementation limits, not architecture or ELF format claims.

Generation stages all three complete files beside their final destinations, so
the line table records the final source directory. Publication uses individual
atomic replacements and reverse-order rollback on observed failure/cancellation.
It is not a filesystem-wide three-file atomic operation or a crash-recovery
transaction. Conflicting concurrent changes are preserved, with retained backup
paths in the failure diagnostics. This publisher is not the executable backup,
durability, receipt or recovery implementation required by #72.
