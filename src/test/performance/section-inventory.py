#!/usr/bin/env python3
"""Measure emitted section/string/location duplication without changing artifacts."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct


def inspect(path):
    data = path.read_bytes()
    assert data[:4] == b'\x7fELF' and data[4] in (1, 2) and data[5] in (1, 2)
    order = '<' if data[5] == 1 else '>'
    if data[4] == 2:
        table, = struct.unpack_from(order + 'Q', data, 40)
        width, count, names_index = struct.unpack_from(order + 'HHH', data, 58)
        layout = order + 'IIQQQQIIQQ'
    else:
        table, = struct.unpack_from(order + 'I', data, 32)
        width, count, names_index = struct.unpack_from(order + 'HHH', data, 46)
        layout = order + 'IIIIIIIIII'
    assert width == struct.calcsize(layout) and table > 0
    zero = struct.unpack_from(layout, data, table)
    count = count or zero[5]
    names_index = zero[6] if names_index == 0xffff else names_index
    assert 0 < names_index < count and table + count * width <= len(data)
    headers = [struct.unpack_from(layout, data, table + index * width) for index in range(count)]
    strings = headers[names_index]
    names = data[strings[4]:strings[4] + strings[5]]
    sections = {}
    for header in headers:
        name = names[header[0]:].split(b'\0', 1)[0].decode('ascii')
        if not name.startswith('.debug_'):
            continue
        assert not header[2] & 0x800, 'inventory expects uncompressed emitted sections'
        assert header[4] + header[5] <= len(data)
        assert name not in sections
        sections[name] = data[header[4]:header[4] + header[5]]
    result = {'sha256': hashlib.sha256(data).hexdigest(), 'fileBytes': len(data),
        'sectionBytes': {name: len(value) for name, value in sections.items()},
        'sectionSha256': {name: hashlib.sha256(value).hexdigest() for name, value in sections.items()}}
    if '.debug_str' in sections:
        strings = sections['.debug_str']
        assert strings.endswith(b'\0')
        counts = Counter(strings[:-1].split(b'\0'))
        result['strings'] = {'entries': sum(counts.values()), 'unique': len(counts),
            'duplicateBytes': sum((count - 1) * (len(value) + 1) for value, count in counts.items())}
    if '.debug_loclists' in sections:
        locations = sections['.debug_loclists']
        length, version, address_size, segment_size, offsets = struct.unpack_from(order + 'IHBBI', locations)
        assert length == len(locations) - 4 and version == 5 and address_size in (4, 8)
        assert segment_size == 0 and offsets == 0, 'inventory expects current Forge list form'
        cursor = start = 12
        lists, addresses, expressions = Counter(), Counter(), Counter()
        address_bytes = 0
        while cursor < len(locations):
            kind = locations[cursor]
            cursor += 1
            if kind == 0:
                lists[locations[start:cursor]] += 1
                start = cursor
                continue
            assert kind == 7, 'unexpected location entry; do not infer an indexing estimate'
            for unused in range(2):
                addresses[locations[cursor:cursor + address_size]] += 1
                cursor += address_size
                address_bytes += address_size
            size, shift = 0, 0
            while True:
                byte = locations[cursor]
                cursor += 1
                size |= (byte & 127) << shift
                shift += 7
                assert shift <= 63
                if byte < 128:
                    break
            assert cursor + size <= len(locations)
            expressions[locations[cursor:cursor + size]] += 1
            cursor += size
        assert cursor == start == len(locations)
        result['locations'] = {'lists': sum(lists.values()), 'uniqueLists': len(lists),
            'exactDuplicateListBytes': sum((count - 1) * len(value) for value, count in lists.items()),
            'addressOperands': sum(addresses.values()), 'uniqueAddressOperands': len(addresses),
            'currentAddressBytes': address_bytes,
            'uniqueAddressPoolBytesWithoutHeaderOrIndexes': len(addresses) * address_size,
            'expressions': sum(expressions.values()), 'uniqueExpressions': len(expressions)}
    assert path.read_bytes() == data, 'artifact changed during inventory'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('artifact', type=Path, nargs='+')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = {'status': 'PASS', 'artifacts': {str(p.resolve()): inspect(p) for p in args.artifact},
        'scope': 'Observed uncompressed Forge section bytes and exact duplication only. '
            'Not an implementation, performance measurement or proof of consumer compatibility.'}
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=4)
        stream.write('\n')


if __name__ == '__main__':
    main()
