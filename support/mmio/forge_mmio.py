"""Explicit GDB MMIO snapshots. Source manually; no auto-load or pretty-printers.

A profile records analyst assertions, not inferred device semantics. RSP packet
width is not a bus guarantee; every snapshot requires the named transport contract.
"""
import hashlib
import json
from pathlib import Path
import re

import gdb


def require(condition, message):
    if not condition:
        raise ValueError(message)


def keys(value, expected):
    require(isinstance(value, dict) and set(value) == set(expected.split()), 'invalid profile fields')


def label(value):
    require(isinstance(value, str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,79}', value), 'invalid profile label')
    return value


def integer(value, low, high):
    require(type(value) is int and low <= value <= high, 'invalid profile integer')
    return value


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def file_hash(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


class Profile:
    def __init__(self, path, sidecar):
        self.sidecar = Path(sidecar).resolve(strict=True)
        with Path(path).open('rb') as stream:
            data = stream.read(65537)
        require(len(data) <= 65536, 'MMIO profile exceeds 64 KiB')
        self.data = json.loads(data, object_pairs_hook=unique_object)
        p = self.data
        keys(p, 'schema sidecar_sha256 architecture address_bits byteorder transport registers')
        require(type(p['schema']) is int and p['schema'] == 1, 'unsupported MMIO profile schema')
        require(isinstance(p['sidecar_sha256'], str) and re.fullmatch('[0-9a-f]{64}', p['sidecar_sha256']), 'invalid sidecar hash')
        require(isinstance(p['architecture'], str) and 0 < len(p['architecture']) <= 80, 'invalid architecture')
        require(type(p['address_bits']) is int and p['address_bits'] in (32, 64), 'unsupported address size')
        require(p['byteorder'] in ('little', 'big'), 'invalid byte order')
        keys(p['transport'], 'id evidence')
        label(p['transport']['id'])
        require(isinstance(p['transport']['evidence'], str) and 0 < len(p['transport']['evidence']) <= 4096,
            'transport evidence is required')
        require(isinstance(p['registers'], list) and 0 < len(p['registers']) <= 128, 'invalid register inventory')
        names = set()
        for r in p['registers']:
            keys(r, 'name address width read_effect views')
            require(label(r['name']) not in names, 'duplicate register name')
            names.add(r['name'])
            require(isinstance(r['address'], str) and re.fullmatch(r'0x[0-9a-fA-F]+', r['address']), 'invalid address')
            address = int(r['address'], 16)
            require(type(r['width']) is int and r['width'] in (1, 2, 4, 8), 'unsupported access width')
            require(address % r['width'] == 0 and address + r['width'] <= 1 << p['address_bits'], 'unaligned or overflowing register')
            require(r['read_effect'] in ('none', 'read-clear', 'read-increment', 'unknown', 'write-only'), 'unknown read policy')
            require(isinstance(r['views'], list) and 0 < len(r['views']) <= 16, 'invalid view inventory')
            view_names = set()
            for view in r['views']:
                keys(view, 'name type offset')
                require(label(view['name']) not in view_names, 'duplicate view name')
                view_names.add(view['name'])
                require(isinstance(view['type'], str) and 0 < len(view['type']) <= 256, 'invalid view type')
                integer(view['offset'], 0, r['width'] - 1)
        self.verify()

    def verify(self):
        p = self.data
        require(file_hash(self.sidecar) == p['sidecar_sha256'], 'stale or mismatched MMIO sidecar')
        with self.sidecar.open('rb') as stream:
            header = stream.read(20)
        require(len(header) == 20 and header[:4] == b'\x7fELF' and header[4] in (1, 2) and header[5] in (1, 2), 'invalid ELF identity')
        require((32 if header[4] == 1 else 64) == p['address_bits'] and
            ('little' if header[5] == 1 else 'big') == p['byteorder'], 'profile disagrees with ELF identity')
        matches = [o for o in gdb.objfiles() if Path(o.filename).resolve() == self.sidecar]
        require(len(matches) == 1, 'profile sidecar must be loaded exactly once')
        self.owner = matches[0]
        inferior = gdb.selected_inferior()
        require(inferior.architecture().name() == p['architecture'], 'target architecture mismatch')
        require(gdb.lookup_type('void').pointer().sizeof * 8 == p['address_bits'], 'target address size mismatch')
        word = gdb.lookup_type('unsigned int')
        require(word.sizeof == 4, 'unsupported target integer size')
        probe = int(gdb.Value(b'\x01\x00\x00\x00', word))
        require(probe == (1 if p['byteorder'] == 'little' else 1 << 24), 'target byte order mismatch')

    def views(self, register):
        result = []
        for view in register['views']:
            t = gdb.lookup_type(view['type'])
            require(t.objfile == self.owner, 'view type belongs to a different debug object')
            require(0 < t.sizeof <= register['width'] - view['offset'], 'view extends beyond selected register')
            validate_type(t, 0, [128])
            result.append((view, t))
        return result

    def snapshot(self, name, transport):
        self.verify()
        require(transport == self.data['transport']['id'], 'explicit transport contract selection required')
        register = next((r for r in self.data['registers'] if r['name'] == name), None)
        require(register is not None, 'unknown register')
        require(register['read_effect'] not in ('unknown', 'write-only'), 'register read policy prohibits access')
        views = self.views(register)
        inferior = gdb.selected_inferior()
        require(inferior.threads() and all(t.is_stopped() for t in inferior.threads()), 'target must be stopped')
        connection = inferior.connection
        require(isinstance(connection, gdb.RemoteTargetConnection), 'only explicit remote packet snapshots are supported')
        address, width = int(register['address'], 16), register['width']
        # Bypass GDB memory caches/prefetch and issue exactly one packet. The stub
        # still determines physical transactions; never retry a failed device read.
        reply = bytes(connection.send_packet('m%x,%x' % (address, width)))
        require(re.fullmatch(b'[0-9a-fA-F]{%d}' % (width * 2), reply) is not None,
            'MMIO read failed or returned a partial reply; device may already have side effects; no retry')
        raw = bytes.fromhex(reply.decode('ascii'))
        decoded = {}
        for view, t in views:
            value = gdb.Value(raw[view['offset']:view['offset'] + t.sizeof], t)
            require(not value.is_lazy, 'snapshot unexpectedly depends on target memory')
            decoded[view['name']] = decode(value)
        return {'register': name, 'address': register['address'], 'width': width,
            'read_effect': register['read_effect'], 'transport': transport,
            'raw': raw.hex(), 'views': decoded}


def validate_type(t, depth, budget):
    t = t.strip_typedefs()
    budget[0] -= 1
    require(depth <= 8 and budget[0] >= 0, 'MMIO view exceeds decoding limits')
    if t.code in (gdb.TYPE_CODE_INT, gdb.TYPE_CODE_ENUM, gdb.TYPE_CODE_BOOL, gdb.TYPE_CODE_CHAR):
        return
    require(t.code in (gdb.TYPE_CODE_STRUCT, gdb.TYPE_CODE_UNION), 'unsupported MMIO view type; pointers are never followed')
    fields = t.fields()
    require(len(fields) <= 64 and len({f.name for f in fields}) == len(fields), 'ambiguous MMIO fields')
    for field in fields:
        require(field.name is not None and not field.is_base_class and hasattr(field, 'bitpos'), 'unsupported MMIO member')
        require(field.bitpos >= 0 and field.bitpos + (field.bitsize or field.type.sizeof * 8) <= t.sizeof * 8,
            'MMIO field exceeds view storage')
        validate_type(field.type, depth + 1, budget)


def decode(value):
    """Return only Python scalars/containers; no lazy values or pretty-printers."""
    t = value.type.strip_typedefs()
    if t.code in (gdb.TYPE_CODE_STRUCT, gdb.TYPE_CODE_UNION):
        return {f.name: decode(value[f]) for f in t.fields()}
    return int(value)


class MmioCommand(gdb.Command):
    """forge-mmio load PROFILE SIDECAR | snapshot REGISTER TRANSPORT

    Loading performs no device reads. Each snapshot is an explicit read with the
    profile's documented effects. No automatic repetition, polling, or writes.
    """
    def __init__(self):
        super().__init__('forge-mmio', gdb.COMMAND_DATA)
        self.profile = None

    def invoke(self, argument, from_tty):
        self.dont_repeat()
        args = gdb.string_to_argv(argument)
        try:
            require(len(args) == 3, 'usage: forge-mmio load PROFILE SIDECAR | snapshot REGISTER TRANSPORT')
            if args[0] == 'load':
                self.profile = None
                self.profile = Profile(args[1], args[2])
                gdb.write('MMIO profile loaded; no device reads performed.\n')
            else:
                require(args[0] == 'snapshot' and self.profile is not None, 'load an MMIO profile first')
                gdb.write(json.dumps(self.profile.snapshot(args[1], args[2]), sort_keys=True, ensure_ascii=True) + '\n')
        except (ValueError, OSError, gdb.error) as error:
            raise gdb.GdbError(str(error)) from error


MmioCommand()
