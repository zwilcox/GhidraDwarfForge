"""Remove only section-table header fields from an owned MIPS FP32 fixture."""
import hashlib
import json
from pathlib import Path
import struct
import sys

path = Path(sys.argv[1])
before = path.read_bytes()
assert before[:5] == b'\x7fELF\x01' and before[5] in (1, 2)
order = '<' if before[5] == 1 else '>'
assert struct.unpack_from(order + 'H', before, 18)[0] == 8
offset = struct.unpack_from(order + 'I', before, 28)[0]
width, count = struct.unpack_from(order + 'HH', before, 42)
assert width == 32 and 0 < count < 65535
records = [struct.unpack_from(order + '8I', before, offset + i * width) for i in range(count)]
abi, = [r for r in records if r[0] == 0x70000003]
assert abi[4] == abi[5] == 24
fields = struct.unpack_from(order + 'H6B4I', before, abi[1])
assert fields == (0, 32, 2, 1, 1, 0, 1, 0, 0, 1, 0)
after = bytearray(before)
after[32:36] = bytes(4)
after[46:52] = bytes(6)
assert after[offset:offset + count * width] == before[offset:offset + count * width]
assert after[abi[1]:abi[1] + 24] == before[abi[1]:abi[1] + 24]
path.write_bytes(after)
print(json.dumps({'status': 'OWNED_FP32_SECTIONLESS_FIXTURE', 'size': len(after),
    'beforeSha256': hashlib.sha256(before).hexdigest(),
    'afterSha256': hashlib.sha256(after).hexdigest(), 'abiOffset': abi[1],
    'abiBytes': before[abi[1]:abi[1] + 24].hex()}, indent=4))
