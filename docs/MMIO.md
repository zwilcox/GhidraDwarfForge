# MMIO register views and access policy

**PRESENT, UNVERIFIED in hosted CI:** the explicit GDB snapshot helper and profile
are implemented, with local instrumented tests against real Forge sidecars.
Saved-program qualifier/alias and layout checks also pass locally. This does not
establish physical bus behavior; the remaining acceptance work is listed below.

## Reference experiment

Run the bounded experiment through the local storage guard:

```bash
python3 support/storage-guard.py run --cwd "$PWD" -- \
    python3 src/test/research/mmio-access/experiment.py \
    --results "$PWD/.forge-work/scratch/mmio-reference"
```

The output directory must not exist. The first profile uses native GCC,
x86-64 little-endian compiler DWARF, LLVM verification, and GDB connected to a
source-written RSP target. No application executes on that target. Its two
device registers require aligned 32-bit accesses: status clears on read and
the adjacent counter increments on read. The target separately records remote
requests and emulated device callbacks. A deliberately incorrect transport
splits requests into bytes, which the device rejects.

The C fixture has const/volatile qualifiers, overlapping union views, enum
flags, reserved bits, signed and cross-byte fields, and a packed one-byte
aggregate whose declared integer base type occupies four bytes. Original
register bytes come from the compiled ELF's `.mmio` section and are checked
against explicit values before testing. This is a reference for future Forge
comparison, not recovered-type evidence.

**CONFIRMED locally** with Ubuntu GDB 15.1:

| Operation | Observed access and implication |
| --- | --- |
| `ptype peripheral` | No device read. Type inspection does not prove runtime access behavior. |
| Separate field prints with `nocache` | Repeated reads of status; later fields observe the cleared value. They are not one coherent sample. |
| Printing the eight-byte device aggregate | One eight-byte remote request, split into two four-byte callbacks. Both registers have side effects. |
| Printing the packed byte view with a `32 nocache` region | One-byte remote request and rejected one-byte callback. The region setting does not make this direct print safe on the tested remote path. |
| Cached field print | Prefetch reaches both registers; subsequent field values may come from cached data. |
| One uncached four-byte snapshot | One four-byte request and callback; all decoded fields use the same bytes. |
| Byte-splitting transport | Even a four-byte request produces an invalid one-byte callback. Packet length does not prove the device's access width. |

The experiment verifies the active `info mem` attributes, request traces,
callback widths/effects, values, and absence of fabricated snapshots after a
device rejection. GDB can return zero after command errors followed by a
successful detach, so exit status alone is not the negative-test oracle.

The separate `src/test/research/mmio-access/layout.py` test compiles the same
fixture for x86-64 and MIPS32 in both byte orders, then uses `gdb-multiarch` to
inspect the compiler ELF's static memory. It checks exact addresses, storage
widths, signed cross-byte fields, enum constants, union offsets, and packed
views against explicit per-ABI values and section bytes. A changed-register
control preserves type metadata but changes both field values and the raw word;
the value oracle rejects it. Compiler inputs and the original ELF stay unchanged.

```bash
python3 support/storage-guard.py run --cwd "$PWD" -- \
    python3 src/test/research/mmio-access/layout.py \
    --results "$PWD/.forge-work/scratch/mmio-layout"
```

Use `--targets x86_64`, `mips32be` or `mips32le` to select available toolchains.
These static layout checks do not execute MIPS firmware or establish MIPS device
access behavior. CI runs them in the corresponding target lanes and runs the
instrumented access experiment in the x86-64 lane.

GDB documents separate memory access, width and cache attributes, and the
remote protocol represents a memory read as an address and byte count. These
interfaces must be distinguished from the target stub's device accesses.
See the [memory-region manual](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Memory-Region-Attributes.html)
and [remote packet specification](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Packets.html).

## Production evidence and remaining requirements

### Extraction audit

**CONFIRMED locally:** `GhidraTypeGraph` selects primary and secondary non-default
labels at defined data objects in loaded memory. It does not require initialized
bytes, so an uninitialized peripheral block is eligible. Each name retains its
namespace, actual address and shared object type. Names alone never merge
different addresses. Before numeric address conversion, overlays, mapped blocks
and nondefault address spaces are omitted with a diagnostic because their runtime
mapping is unproved. Arbitrary offcut or independently typed overlapping views
still require an explicit MMIO profile; a secondary label at an object's start
describes that same complete object.

The aggregate extractor preserves each bitfield's actual storage size
with `BitFieldDataType.getStorageSize()`, separately from its base type. It emits
union member offsets, enum values and signedness. The generic type graph and
writer can represent qualified types. **CONFIRMED locally:** extraction now
wraps the references of data objects with supported explicit constant/volatile
settings, including function-owned statics. Aggregate members use supported
component default settings. The shared base type remains unchanged, and matching
qualified references reuse one node. Block/processor flags and unsupported
aggregate settings do not imply C qualifiers. Arbitrary per-instance overrides on nested components are not inferred.
The saved MMIO profile explicitly represents combined `const volatile` views
without relying on unsupported aggregate mutability settings.

The DWARF writer gives a defined global an address expression. It does not encode
device width, read-clear behavior, or a debugger cache policy. Those require an
explicit access contract, not interpretation of a variable name or `volatile`.

**CONFIRMED by the saved-program evidence test:** on Ghidra 12.0.3, x86-64,
Cortex-M and big-endian MIPS programs retain these distinctions after immutable
database reopening:

- A loaded, uninitialized peripheral block can be volatile and read-only while
  its data objects report neither explicit constant nor volatile qualification.
- Explicit object mutability settings survive saving. Setting constant after
  volatile replaces the mode; it does not represent `const volatile`.
- Two labels at one address retain distinct identities with one primary label.
- An overlay and ordinary address can have the same numeric offset but remain
  different addresses. A byte-mapped alias remains a mapped block with its own
  address, not proof of an independent hardware register.

The `ghidraMmioEvidenceSmoke` Gradle task also checks aggregate settings: Ghidra
rejects the mutability key on a structure instance with an expected diagnostic.
The union component also remains unqualified after an attempted default setting.
Its supported scalar component does report the volatile setting. An attempted
settings write is therefore insufficient evidence of type semantics.

The task checks these properties, unchanged program modification counters and
unchanged saved database bytes/timestamps. Run through the storage guard with the normal Ghidra/Java
environment. It exercises the real Ghidra database API, but does not validate
Forge emission, physical reads or unsupported processor profiles.

### Installed exporter probe

`src/test/research/mmio-access/forge.py` uses the layout reference directories,
strips their compiler debug information, applies types and settings with
`ApplyMmioFixture.java`, saves the Ghidra program, and exports it through the
installed headless wrapper. It reports gaps explicitly; a successful probe
process is not a feature-completion result.

**CONFIRMED on the current exporter:** x86-64 and both MIPS32 byte orders retain
the tested field values, flags, offsets and widths. GNU/LLVM/pinned validation,
original-input preservation and repeated sidecar/source determinism pass.
The scalar counter's saved volatile setting and secondary global name now survive
into GDB on all three profiles, with unchanged field values and layouts. The
alias is checked for its exact address and actual raw/counter values. The probe
rejects a missing qualifier, alias mismatch or changed project files. The explicit snapshot helper now also has local instrumented checks against
these artifacts, described below. Hosted validation remains pending.

**HISTORICAL at `9f57035e`:** the existing ELF-project wrapper also changed
Ghidra's index/journal backup files. Fix `3fb950d0` applies the raw-firmware
read-only project opener to all saved exports. The repeated installed probe now
preserves project files on all three targets; separate root/nested tests preserve
file bytes and modification times for stripped and unstripped ELF inputs.
Hosted validation of that fix is still pending.

```bash
python3 support/storage-guard.py run --cwd "$PWD" -- \
    python3 src/test/research/mmio-access/forge.py \
    --ghidra /path/to/ghidra-with-packaged-extension \
    --references "$PWD/.forge-work/scratch/mmio-layout" \
    --results "$PWD/.forge-work/scratch/mmio-forge"
```

Use the normal Java 21 environment and set `DWARFDUMP` to the pinned validator.
The probe reads static ELF memory; it does not establish live device behavior.

### Saved analyst profile and export

`GhidraDwarfForgeMmioProfile.java` explicitly validates and stores a selection in
the current program's `GhidraDwarfForge` options under `MMIO profile JSON`. Run it
from Script Manager and select the JSON file, or supply that file as its one
headless script argument. Applying the profile changes the program's analyst
metadata; save the program to retain it. It does not read a device or modify an
input executable. Invalid selections and cancellation do not commit the change.

The saved selection describes Ghidra addresses and runtime addresses separately.
It never assumes an image rebase or PIE load bias also relocates a hardware
register. Each Ghidra address must identify ordinary loaded default-space memory
in one complete block; initialized bytes are not required. Overlay, mapped,
missing and out-of-block regions are rejected. Runtime addresses and read policies
are explicit analyst assertions, checked for width/alignment rather than inferred.
Exact data-type paths select types from the saved program, including types not
otherwise used by a listing object. Independent overlapping views share captured
bytes without changing ordinary global-variable locations or merging names.

Example saved selection for the fixture's x86-64 program:

```json
{
    "schema": 1,
    "language": "x86:LE:64:default",
    "architecture": "i386:x86-64",
    "transport": {
        "id": "instrumented-word32",
        "evidence": "Source-modeled Target/Device callback trace; no physical bus claim"
    },
    "registers": [{
        "name": "status",
        "address": "ram:40000000",
        "runtime_address": "0x40000000",
        "width": 4,
        "read_effect": "read-clear",
        "views": [{
            "name": "register",
            "datatype": "/ForgeMmioFixture/Register",
            "offset": 0,
            "qualifiers": ["const", "volatile"]
        }]
    }]
}
```

Then select `--mmio` in the Bash wrapper/export script, or `-Mmio` in PowerShell.
The exporter publishes `<sidecar>.mmio.json` with the sidecar/source generation,
using the existing recoverable companion publication path. It includes the exact
sidecar hash and generated canonical type aliases. The aliases preserve the
selected qualifiers and avoid choosing a type merely by its display name. The
underlying data objects and shared types remain unchanged. The default export
without this option does not apply the profile or add its companion.

MMIO profile export cannot be combined with automatic formatter generation or
attachment preparation. This prevents a selected MMIO generation from installing
aggregate formatters that could traverse read-sensitive registers. The snapshot
helper itself does not install printers or disable independently installed scripts;
normal GDB prints and third-party printers retain their own access behavior.

**CONFIRMED locally:** immutable saved-program tests retain combined qualifiers
on x86-64, Cortex-M and MIPS BE, with no database or modification-counter change.
Installed export tests on x86-64 and both MIPS byte orders prove combined
`const volatile`, independent packed views, canonical type aliases, validators,
input/project preservation and byte-identical sidecar/source/profile reruns. The
profile JSON uses stable field ordering; an initial unordered-map implementation
failed the repeat check and was corrected. Hosted validation remains pending.

### Explicit GDB snapshots

`support/mmio/forge_mmio.py` is a manually loaded helper. It registers one command,
with no event hooks, pretty-printers, polling, target writes, or automatic reads.
The profile is JSON data supplied by the analyst, bound to the exact loaded
sidecar SHA-256. It declares target identity, register addresses, aligned widths,
known read effects, overlapping type views and a transport evidence reference.
It does not derive hardware semantics from names or qualifiers. A profile is an
analyst assertion; a transport name is not proof that a physical probe honors it.

Example profile (replace the hash and transport evidence with actual evidence):

```json
{
    "schema": 1,
    "sidecar_sha256": "<64 lowercase hex digits from sha256sum firmware.dbg>",
    "architecture": "i386:x86-64",
    "address_bits": 64,
    "byteorder": "little",
    "transport": {
        "id": "instrumented-word32",
        "evidence": "experiment.py Target/Device callback trace for this exact transport"
    },
    "registers": [{
        "name": "status",
        "address": "0x40000000",
        "width": 4,
        "read_effect": "read-clear",
        "views": [
            {"name": "register", "type": "union Register", "offset": 0},
            {"name": "packed", "type": "struct ByteFields", "offset": 0}
        ]
    }]
}
```

With the original and sidecar already loaded and the remote target stopped:

```gdb
source /path/to/GhidraDwarfForge/support/mmio/forge_mmio.py
forge-mmio load /path/to/profile.json /path/to/firmware.dbg
forge-mmio snapshot status instrumented-word32
```

Every snapshot is an explicit potentially destructive read. A `read-clear`
register clears on that read; another explicit snapshot observes its new state.
Unknown and write-only policies are rejected. The command disables GDB command
repetition and requires the transport identifier on every request. Profiles are
not automatically loaded from the executable, saved program, or working directory.

The helper checks ELF class/byte order, active target architecture/pointer width,
sidecar identity, type ownership and view bounds before access. Views must be
integer/enum/boolean aggregates; pointers, references and unsupported members are
rejected before the read. Each view must fit wholly within the selected register.
It sends one explicit RSP `m` packet through `RemoteTargetConnection.send_packet`,
bypassing GDB's memory cache and prefetch. It never retries a failed or partial
reply: the device might already have applied a side effect. It constructs eager
GDB values from captured bytes and returns only JSON scalars/containers. No target
value, pointer dereference, or third-party pretty-printer participates in decoding.
See GDB's [connection API](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Connections-In-Python.html)
and [buffer value constructor](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Values-From-Inferior.html).

**CONFIRMED locally:** `helper.py` compares unchanged compiler references with
Forge sidecars on x86-64, MIPS32 big-endian and MIPS32 little-endian. With GDB cache
explicitly enabled, each snapshot causes one four-byte request and one four-byte
callback. Union, packed, signed cross-byte and enum values decode from that same
sample; the adjacent increment-on-read register remains untouched. A second
explicit read observes zero after read-clear. Type/profile loading causes no
peripheral access. Unknown/write-only policy, unaligned address, stale hash,
wrong transport/architecture/byte order and oversized views fail without reads.
A byte-splitting transport is rejected by the peripheral. A partial reply after a
successful read produces no snapshot and is not retried.

The test's MIPS stub advertises the documented CPU/CP0/FPU register description
but does not execute code or emulate a dynamic loader. GDB's missing dynamic-linker
breakpoint warning must reproduce exactly with the unchanged compiler reference;
other warnings are rejected. This limitation is separate from DWARF validation.
The companion `widths.py` test validates aligned one-, two- and eight-byte
callbacks on the same three targets against compiler and Forge artifacts. It
checks read-clear, unchanged and read-increment values, repeated snapshots with
GDB caching enabled, and preservation of an adjacent read-clear register. A
transport that substitutes byte reads is rejected for the wider registers,
without retries or changes to their state. Together these tests cover all four
profile widths on the instrumented transport. Profiles can be supplied externally or generated from the explicitly saved
program selection described above; neither route infers device semantics. Do not infer broader hardware support from these tests.

```bash
python3 support/storage-guard.py run --cwd "$PWD" -- \
    python3 -B src/test/research/mmio-access/helper.py --target mips32be \
    --original /path/to/input.elf --sidecar /path/to/firmware.dbg \
    --reference /path/to/compiler-reference.elf \
    --profile /path/to/firmware.dbg.mmio.json \
    --results "$PWD/.forge-work/scratch/mmio-helper"
```

CI runs this test with the packaged helper after installed Forge export in all
three target lanes. Hosted validation is still pending on the local MMIO branch.

### Publication and saved-project protection

`failures.py` opens the saved fixture without write access and runs the installed
exporter through cancellation during profile reading, type contribution, native
production, ELF writing and profile rendering. It checks both absent and existing
output generations. A valid saved selection that exceeds the rendered profile's
size limit exercises a late failure after staging the sidecar and source.

The controls also reject formatter combinations, profile hard links to the input
or project marker, and outputs inside the saved project. A final successful retry
must reproduce the original generation. The harness compares input/output hashes
and the saved project inventory; a cancellation or exception alone is insufficient.
Raw and MMIO exports share the saved-project output protection.

### Remaining validation

- Complete raw-firmware integration controls and hosted validation of the
  saved-program configuration and publication failure/cancellation flow.
- Exercise profile replacement, stale loaded artifacts, malformed inventories and
  additional unsupported type controls through the packaged helper.
- Review optional formatter interaction so read-sensitive registers are not
  traversed automatically when a formatter is explicitly enabled elsewhere.
- Complete structural and behavioral hosted validation and the issue acceptance
  audit. The local results do not substitute for that gate.

The callback log proves the behavior of this source-modeled peripheral; it does
not establish the bus behavior of an arbitrary probe, QEMU machine or device.
