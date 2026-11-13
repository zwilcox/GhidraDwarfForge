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

The aggregate extractor already preserves each bitfield's actual storage size
with `BitFieldDataType.getStorageSize()`, separately from its base type. It emits
union member offsets, enum values and signedness. The generic type graph and
writer can represent qualified types, but the current Ghidra extractor has no
const/volatile conversion in its type dispatch. A compiler-reference qualifier
test therefore cannot establish preservation from a saved Ghidra program. The
next fixture must explicitly exercise Ghidra's data-instance settings and
document the distinction between object qualifiers and member type information.

The DWARF writer gives a defined global an address expression. It does not encode
device width, read-clear behavior, or a debugger cache policy. Those require an
explicit access contract, not interpretation of a variable name or `volatile`.

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
