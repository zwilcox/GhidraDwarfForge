# MMIO register views and access policy

**PLANNED:** issue #118's production profile and debugger helper. Existing
aggregate/bitfield/enum export does not establish safe peripheral access. This
document records the first compiler/device reference experiment; it does not
claim Forge MMIO export or physical hardware validation.

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

## Production requirements still pending

### Extraction audit

**CONFIRMED in the current implementation:** `GhidraTypeGraph` selects primary,
non-default labels on loaded memory blocks with defined data. It does not require
initialized bytes, so an uninitialized peripheral block is eligible. However,
secondary labels are skipped; the numeric global model loses address-space
identity. Neither behavior establishes overlapping MMIO views or safe overlay
mapping. A peripheral profile must retain and validate the actual Ghidra address
space before converting to a runtime address, and distinguish explicit aliases
from coincident names or offsets.

The aggregate extractor preserves each bitfield's actual storage size
with `BitFieldDataType.getStorageSize()`, separately from its base type. It emits
union member offsets, enum values and signedness. The generic type graph and
writer can represent qualified types. **CONFIRMED locally:** extraction now
wraps the references of data objects with supported explicit constant/volatile
settings, including function-owned statics. Aggregate members use supported
component default settings. The shared base type remains unchanged, and matching
qualified references reuse one node. Block/processor flags and unsupported
aggregate settings do not imply C qualifiers. Arbitrary per-instance overrides
on nested components and combined `const volatile` aggregate views still need
an explicit representation in the MMIO profile.

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
The scalar counter's saved volatile setting now survives into GDB on all three
profiles, with unchanged field values and layouts. The probe rejects a missing
qualifier or changed project files. The secondary global label remains omitted;
the access profile/helper and instrumented production reads are still pending.

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

### Remaining validation

- Audit actual Ghidra address spaces, data types, aliases and storage evidence;
  preserve analyst-defined views without deriving hardware semantics from names.
- Define an explicit access profile, including register width/alignment,
  readability, effects and a tested target/transport contract. Unknown and
  read-sensitive registers must not be polled or traversed automatically.
- Read a selected register once, then decode immutable captured bytes. Qualifiers
  and pretty-printer expressions must not trigger additional lazy target reads.
- Compare real Forge artifacts against compiler/raw-byte oracles, including
  packed storage, cross-byte signed fields, flags, reserved bits and overlapping
  names. Extend the reference to applicable 32/64-bit and endian profiles.
- Prove debugger behavior with the production helper and an instrumented target,
  preserve input files and addresses, run structural validation and required CI.

The current fixture alone satisfies none of the production completion claims.
Its callback log proves the behavior of this source-modeled peripheral; it does
not establish the bus behavior of an arbitrary probe, QEMU machine or device.
