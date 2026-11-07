"""Trusted formatter runtime; MANIFEST is separately decoded data, never code."""
import hashlib
import json
import os

MANIFEST = None
_states = {}
_gdb_owner = None
_gdb_lookup = None
_lldb_debugger = None
_lldb_target = None
_lldb_module = None
_lldb_category = None
_rules = []


def _label(text):
    # Debugger summary strings are rendered verbatim. Escape controls, delimiters
    # and non-ASCII instead of allowing stored labels to alter terminal output.
    return json.dumps(text, ensure_ascii=True)[1:-1]


def flags_text(value, rule):
    width = rule['size'] * 8
    mask = (1 << width) - 1
    bits = value & mask
    grouped = {}
    for flag in rule['flags']:
        grouped.setdefault(int(flag['bits'], 16), []).append(_label(flag['name']))
    names = []
    known = 0
    for flag, aliases in sorted(grouped.items()):
        if flag == 0 and bits == 0 or flag != 0 and bits & flag == flag:
            names.append('='.join(aliases))
            known |= flag
    unknown = bits & ~known & mask
    if unknown:
        names.append('unknown=0x%x' % unknown)
    raw = bits - (1 << width) if rule['signed'] and bits & (1 << (width - 1)) else bits
    return '%s (raw: %d / 0x%0*x)' % (' | '.join(names) or '0', raw, rule['size'] * 2, bits)


def _state(path):
    stat = os.stat(path)
    return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns


def bind_files(companion_path):
    """A moved companion binds only the co-located, byte-identical generation.

    Retain the recorded original path when loading from the export location
    (the output directory can differ from the input directory). After moving the
    bundle, require both named ELF files next to the script. Never search the
    working directory, a symbol path, or a different generation by type name.
    Hash and debugger-module verification still happen before registration.
    """
    directory = os.path.dirname(os.path.realpath(companion_path))
    for artifact in (MANIFEST['original'], MANIFEST['sidecar']):
        name = artifact['name']
        if not name or name in ('.', '..') or os.path.basename(name) != name:
            raise ValueError('invalid Forge formatter artifact basename')
    sidecar = os.path.join(directory, MANIFEST['sidecar']['name'])
    if os.path.normcase(os.path.realpath(sidecar)) != os.path.normcase(os.path.realpath(MANIFEST['sidecar']['path'])):
        MANIFEST['original']['path'] = os.path.join(directory, MANIFEST['original']['name'])
    MANIFEST['sidecar']['path'] = sidecar


def _verify_files():
    if MANIFEST['schema'] != 1:
        raise ValueError('unsupported Forge formatter manifest')
    states = {}
    for artifact in (MANIFEST['original'], MANIFEST['sidecar']):
        path = artifact['path']
        before = _state(path)
        digest = hashlib.sha256()
        with open(path, 'rb') as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(block)
        if _state(path) != before or digest.hexdigest() != artifact['sha256']:
            raise ValueError('stale or mismatched Forge formatter artifact: ' + path)
        states[path] = before
    return states


def _unchanged():
    try:
        return bool(_states) and all(_state(path) == state for path, state in _states.items())
    except OSError:
        return False


def _same_path(left, right):
    try:
        return os.path.samefile(left, right)
    except (OSError, TypeError):
        return False


def _summary(view, depth=0, budget=None):
    if budget is None:
        budget = [32]
    if budget[0] == 0:
        return '<summary limit>'
    budget[0] -= 1
    try:
        if view.unavailable():
            return '<unavailable>'
        kind = view.kind()
        if kind == 'pointer':
            value = view.integer()
            return 'NULL' if value == 0 else '0x%x' % value
        if kind == 'integer':
            return str(view.integer())
        if kind == 'float':
            return view.floating()
        if kind not in ('aggregate', 'array'):
            return '<raw value available>'
        count = view.count()
        if depth >= 2:
            return '<%d children; expand to inspect>' % count
        parts = []
        for index in range(min(count, 8)):
            name, child = view.child(index)
            parts.append(_label(name) + '=' + _summary(child, depth + 1, budget))
        if count > 8:
            parts.append('... %d more children' % (count - 8))
        return '{' + ', '.join(parts) + '}'
    except (RuntimeError, ValueError, TypeError, OverflowError):
        return '<unavailable>'


class _GdbView:
    def __init__(self, value):
        self.value = value
        self.type = value.type.strip_typedefs()

    def unavailable(self):
        return self.value.is_optimized_out or getattr(self.value, 'is_unavailable', False)

    def kind(self):
        import gdb
        code = self.type.code
        if code == gdb.TYPE_CODE_PTR:
            return 'pointer'
        if code in (gdb.TYPE_CODE_INT, gdb.TYPE_CODE_ENUM, gdb.TYPE_CODE_BOOL, gdb.TYPE_CODE_CHAR):
            return 'integer'
        if code in (gdb.TYPE_CODE_STRUCT, gdb.TYPE_CODE_UNION):
            return 'aggregate'
        if code == gdb.TYPE_CODE_ARRAY:
            return 'array'
        if code == gdb.TYPE_CODE_FLT:
            return 'float'
        return 'other'

    def integer(self):
        return int(self.value)

    def floating(self):
        return str(float(self.value))

    def count(self):
        if self.kind() == 'array':
            low, high = self.type.range()
            return max(0, high - low + 1)
        return len(self.type.fields())

    def child(self, index):
        if self.kind() == 'array':
            offset = self.type.range()[0] + index
            return '[%d]' % offset, _GdbView(self.value[offset])
        field = self.type.fields()[index]
        return field.name or '<anonymous %d>' % index, _GdbView(self.value[field])


class _GdbPrinter:
    def __init__(self, value, rule):
        self.value = value
        self.rule = rule

    def to_string(self):
        if not _unchanged():
            return '<Forge formatter stale; unload to inspect raw value>'
        try:
            view = _GdbView(self.value)
            if view.unavailable():
                return '<unavailable>'
            if self.rule['mode'] == 'flags':
                return flags_text(view.integer(), self.rule)
            return _summary(view)
        except (RuntimeError, ValueError, TypeError, OverflowError):
            return '<unavailable>'

    def children(self):
        if self.rule['mode'] != 'structure':
            return
        # Native fields remain accessible; summary clipping never clips children.
        # Admission limits aggregates to 256 fields; debugger depth settings govern
        # their expansion. Pointers are returned as pointers, never dereferenced.
        import gdb
        view = _GdbView(self.value)
        for index in range(view.count()):
            try:
                name, child = view.child(index)
                yield name, child.value
            except (RuntimeError, ValueError, TypeError):
                yield '<field %d>' % index, gdb.Value('<unavailable>')


def _gdb_type(owner, name):
    import gdb
    symbol = owner.lookup_static_symbol(name) or owner.lookup_global_symbol(name)
    if symbol is None or symbol.addr_class != gdb.SYMBOL_LOC_TYPEDEF:
        raise ValueError('Forge formatter canonical type witness is missing: ' + name)
    result = symbol.type.strip_typedefs().unqualified()
    if result.objfile != owner:
        raise ValueError('Forge formatter type belongs to another symbol module')
    return result


def register_gdb():
    import gdb
    global _states, _gdb_owner, _gdb_lookup, _rules
    states = _verify_files()
    unload()
    owners = [obj for obj in gdb.objfiles() if _same_path(obj.filename, MANIFEST['sidecar']['path'])]
    if len(owners) != 1:
        raise gdb.GdbError('Load the exact Forge sidecar before sourcing its formatters')
    owner = owners[0]
    admitted = []
    for rule in MANIFEST['rules']:
        selected = _gdb_type(owner, rule['alias'])
        if any(selected == _gdb_type(owner, peer) for peer in rule['peers']):
            gdb.write('Forge formatter omitted: ambiguous canonical type ' + _label(rule['key']) + '\n')
            continue
        if selected.sizeof != rule['size']:
            raise gdb.GdbError('Forge formatter type width differs from its export')
        admitted.append((selected, rule))

    def lookup(value):
        if not owner.is_valid() or not _unchanged():
            return None
        typed = value.type.strip_typedefs().unqualified()
        if typed.objfile != owner:
            return None
        for selected, rule in admitted:
            if typed == selected:
                return _GdbPrinter(value, rule)
        return None

    _states, _gdb_owner, _gdb_lookup, _rules = states, owner, lookup, admitted
    registry = getattr(gdb, '_forge_formatters', None)
    if registry is None:
        registry = gdb._forge_formatters = {}

        class Manage(gdb.Command):
            def __init__(self):
                super().__init__('forge-formatters', gdb.COMMAND_DATA)

            def invoke(self, argument, from_tty):
                gdb.write(_manage(gdb._forge_formatters, argument) + '\n')

        Manage()
    previous = registry.get(MANIFEST['sidecar']['sha256'])
    if previous is not None:
        previous.unload()
    owner.pretty_printers.append(lookup)
    import sys
    registry[MANIFEST['sidecar']['sha256']] = sys.modules[__name__]
    gdb.write('Forge formatters loaded: %d selected types; forge-formatters unload disables them\n' % len(admitted))


class _LldbView:
    def __init__(self, value):
        self.value = value.GetNonSyntheticValue()
        self.type = self.value.GetType().GetCanonicalType()

    def unavailable(self):
        return not self.value.IsValid() or self.value.GetError().Fail()

    def kind(self):
        import lldb
        kind = self.type.GetTypeClass()
        if kind & lldb.eTypeClassPointer:
            return 'pointer'
        if kind & (lldb.eTypeClassStruct | lldb.eTypeClassClass | lldb.eTypeClassUnion):
            return 'aggregate'
        if kind & lldb.eTypeClassArray:
            return 'array'
        flags = self.type.GetTypeFlags()
        if flags & lldb.eTypeIsFloat:
            return 'float'
        if flags & lldb.eTypeIsInteger or kind & lldb.eTypeClassEnumeration:
            return 'integer'
        return 'other'

    def integer(self):
        import lldb
        error = lldb.SBError()
        signed = self.type.GetTypeFlags() & lldb.eTypeIsSigned
        value = self.value.GetValueAsSigned(error) if signed else self.value.GetValueAsUnsigned(error)
        if error.Fail():
            raise ValueError('unavailable scalar')
        return value

    def floating(self):
        value = self.value.GetValue()
        if value is None:
            raise ValueError('unavailable float')
        return value

    def count(self):
        return self.value.GetNumChildren()

    def child(self, index):
        value = self.value.GetChildAtIndex(index)
        return value.GetName() or '<anonymous %d>' % index, _LldbView(value)


def lldb_summary(value, internal_dict, options=None):
    if not _unchanged() or value.GetTarget() != _lldb_target:
        return None
    typed = value.GetType().GetCanonicalType().GetUnqualifiedType()
    if typed.GetModule() != _lldb_module:
        return None
    for selected, rule in _rules:
        if typed == selected:
            try:
                view = _LldbView(value)
                if view.unavailable():
                    return '<unavailable>'
                return flags_text(view.integer(), rule) if rule['mode'] == 'flags' else _summary(view)
            except (RuntimeError, ValueError, TypeError, OverflowError):
                return '<unavailable>'
    return None


def lldb_matches(typed, internal_dict):
    # A name-only registration would shadow unrelated modules' formatters even
    # when our summary callback returns None. Recognize the canonical module/type
    # before LLDB selects this formatter, preserving other categories' fallback.
    canonical = typed.GetCanonicalType().GetUnqualifiedType()
    # LLDB 18 supplies a compiler-only SBType to recognizers (GetModule is
    # invalid). Its canonical type identity compares to the module-bound witness;
    # the value callback also verifies the actual value's module and target.
    return _unchanged() and any(
        canonical == selected for selected, rule in _rules)


def _lldb_type(module, name):
    typed = module.FindFirstType(name)
    if not typed.IsValid() or not typed.IsTypedefType():
        raise ValueError('Forge formatter canonical type witness is missing: ' + name)
    typed = typed.GetCanonicalType().GetUnqualifiedType()
    if typed.GetModule() != module:
        raise ValueError('Forge formatter type belongs to another module')
    return typed


def register_lldb(debugger):
    import lldb
    import sys
    global _states, _lldb_debugger, _lldb_target, _lldb_module, _lldb_category, _rules
    states = _verify_files()
    unload()
    target = debugger.GetSelectedTarget()
    modules = [module for module in target.modules if
        _same_path(str(module.GetSymbolFileSpec()), MANIFEST['sidecar']['path'])]
    if len(modules) != 1:
        raise ValueError('Load the exact Forge sidecar before importing its formatters')
    module = modules[0]
    if not _same_path(str(module.GetFileSpec()), MANIFEST['original']['path']):
        raise ValueError('Forge formatter original module differs')
    admitted = []
    for rule in MANIFEST['rules']:
        selected = _lldb_type(module, rule['alias'])
        if any(selected == _lldb_type(module, peer) for peer in rule['peers']):
            print('Forge formatter omitted: ambiguous canonical type ' + _label(rule['key']))
            continue
        if selected.GetByteSize() != rule['size']:
            raise ValueError('Forge formatter type width differs from its export')
        admitted.append((selected, rule))
    name = 'forge-' + MANIFEST['sidecar']['sha256']
    # Category names and callback identifiers contain only generated ASCII hashes.
    category = debugger.CreateCategory(name)
    # A stopped process does not change LLDB's update generation when a sidecar
    # changes on disk. Re-evaluate our file binding instead of reusing an old
    # summary cached on an SBValue.
    options = (lldb.eTypeOptionCascade | lldb.eTypeOptionSkipPointers |
        lldb.eTypeOptionSkipReferences | lldb.eTypeOptionNonCacheable)
    summary = lldb.SBTypeSummary.CreateWithFunctionName(__name__ + '.lldb_summary', options)
    matcher = lldb.SBTypeNameSpecifier(__name__ + '.lldb_matches', lldb.eFormatterMatchCallback)
    if not category.AddTypeSummary(matcher, summary):
        debugger.DeleteCategory(name)
        raise ValueError('LLDB refused formatter registration')
    _states, _rules = states, admitted
    _lldb_debugger, _lldb_target, _lldb_module, _lldb_category = debugger, target, module, name
    if not hasattr(lldb, '_forge_formatters'):
        lldb._forge_formatters = {}
    registry = lldb._forge_formatters.setdefault(debugger.GetID(), {})
    registry[MANIFEST['sidecar']['sha256']] = sys.modules[__name__]
    category.SetEnabled(True)
    command = lldb.SBCommandReturnObject()
    debugger.GetCommandInterpreter().HandleCommand(
        'command script add -o -f ' + __name__ + '.lldb_manage forge-formatters', command)
    if not command.Succeeded():
        unload()
        raise ValueError(command.GetError())
    print('Forge formatters loaded: %d selected types; forge-formatters unload disables them' % len(admitted))


def _manage(registry, argument):
    words = argument.split()
    if words == ['list']:
        return '\n'.join(sorted(registry)) or 'No Forge formatters loaded'
    if words == ['unload']:
        for module in list(registry.values()):
            module.unload()
        return 'Forge formatters unloaded'
    raise ValueError('usage: forge-formatters list|unload')


def lldb_manage(debugger, command, result, internal_dict):
    import lldb
    try:
        result.AppendMessage(_manage(lldb._forge_formatters.get(debugger.GetID(), {}), command))
    except ValueError as error:
        result.SetError(str(error))


def unload():
    global _states
    if _gdb_owner is not None:
        import gdb
        if _gdb_owner.is_valid() and _gdb_lookup in _gdb_owner.pretty_printers:
            _gdb_owner.pretty_printers.remove(_gdb_lookup)
        getattr(gdb, '_forge_formatters', {}).pop(MANIFEST['sidecar']['sha256'], None)
    if _lldb_debugger is not None:
        import lldb
        _lldb_debugger.DeleteCategory(_lldb_category)
        getattr(lldb, '_forge_formatters', {}).get(_lldb_debugger.GetID(), {}).pop(MANIFEST['sidecar']['sha256'], None)
    _states = {}
