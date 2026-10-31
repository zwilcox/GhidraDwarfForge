"""Research-only static mirror, independent of the production writer."""
import struct
from inventory import Inventory, require


def merge(binary, sidecar, output):
    inventory = Inventory(binary)
    data = bytearray(sidecar.read_bytes())
    order, wide = inventory.order, inventory.wide
    header = struct.unpack_from(order + ('HHIQQQIHHHHHH' if wide else 'HHIIIIIHHHHHH'), data, 16)
    section_offset, section_width, count, names_index = header[5], header[10], header[11], header[12]
    fmt = order + ('IIQQQQIIQQ' if wide else 'IIIIIIIIII')
    headers = [list(struct.unpack_from(fmt, data, section_offset + i * section_width)) for i in range(count)]
    names = bytes(data[headers[names_index][4]:headers[names_index][4] + headers[names_index][5]])
    sections = {names[h[0]:names.index(0, h[0])].decode(): i for i, h in enumerate(headers)}
    table_index, strings_index = sections['.symtab'], sections['.strtab']
    table, strings = headers[table_index], headers[strings_index]
    width = inventory.width
    original = bytes(data[table[4]:table[4] + table[5]])
    original_names = bytes(data[strings[4]:strings[4] + strings[5]])
    require(table[7] == len(original) // width, 'probe aliases must all be local')
    aliases = bytearray(original[width:])
    text = bytearray(inventory.names)
    for at in range(0, len(aliases), width):
        name, = struct.unpack_from(order + 'I', aliases, at)
        end = original_names.index(0, name)
        struct.pack_into(order + 'I', aliases, at, len(text))
        text.extend(original_names[name:end + 1])
    split = inventory.locals * width
    records = inventory.records[:split] + aliases + inventory.records[split:]
    table[7] = inventory.locals + len(aliases) // width
    for section, payload in ((strings, text), (table, records)):
        alignment = max(1, section[8])
        data.extend(bytes((-len(data)) % alignment))
        section[4], section[5] = len(data), len(payload)
        data.extend(payload)
    for i in (table_index, strings_index):
        struct.pack_into(fmt, data, section_offset + i * section_width, *headers[i])
    output.write_bytes(data)
    return inventory
