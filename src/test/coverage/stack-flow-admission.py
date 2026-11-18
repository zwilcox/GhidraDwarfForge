"""Admit stack-flow probes only with complete compiler-correlated debugger traces."""
import re


FUNCTIONS = ('flow_diamond', 'flow_kill', 'flow_bypass', 'flow_loop',
    'flow_loop_kill', 'flow_redefine', 'flow_split')
ROLES = ('exec', 'pie', 'pie-rebased')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def hashes(value):
    return isinstance(value, dict) and bool(value) and all(isinstance(key, str)
        and isinstance(digest, str) and re.fullmatch('[0-9a-f]{64}', digest) for key, digest in value.items())


def expected_return(name, seed, choice):
    if name in ('flow_kill', 'flow_loop_kill'):
        return seed ^ 90 if choice else seed
    if name == 'flow_bypass':
        return seed if choice else -12345
    return seed + choice + 1 if name == 'flow_redefine' else seed


def trace(evidence, mode, scenarios):
    result = evidence['debugger'].get(mode)
    require(isinstance(result, dict) and result.get('status') == 'PASS'
        and result.get('navigation') == ['next', 'step'] and result.get('exitCode') == 0,
        'stack-flow debugger navigation or completion failed')
    returns = [{'function': name, 'seed': seed, 'choice': choice,
        'value': expected_return(name, seed, choice)} for seed, choice, name in scenarios]
    require(result.get('returns') == returns, 'stack-flow debugger lacks all 42 expected returns')
    points = result.get('points')
    require(isinstance(points, list) and 0 < len(points) <= 42000
        and all(isinstance(point, dict) for point in points), 'stack-flow instruction trace missing or oversized')
    grouped = {key: [] for key in scenarios}
    order = []
    for point in points:
        key = point.get('seed'), point.get('choice'), point.get('function')
        require(key in grouped, 'unexpected stack-flow debugger scenario')
        grouped[key].append(point)
        if not order or order[-1] != key:
            order.append(key)
    require(order == scenarios, 'stack-flow scenario order or completeness differs')
    for seed, choice, name in scenarios:
        label = evidence['labels']['functions'][name]
        current, definitions, retired = -12345, 0, False
        visits, biases = {}, set()
        rows = grouped[seed, choice, name]
        require(rows[0].get('linkPc') == label['entry'], 'stack-flow entry instruction missing')
        for point in rows:
            require(all(type(point.get(key)) is int for key in ('linkPc', 'pc', 'visit', 'logical')),
                'stack-flow trace lacks numeric instruction/value evidence')
            pc = point['linkPc']
            require(label['entry'] <= pc < label['end'], 'stack-flow instruction outside function')
            if name == 'flow_split':
                require(not label['hole'] <= pc < label['afterhole'], 'stack-flow executes body hole')
            bias = point['pc'] - pc
            require(bias == 0 if evidence['role'] == 'exec' else bias > 0, 'stack-flow runtime bias differs')
            biases.add(bias)
            visits[pc] = visits.get(pc, 0) + 1
            require(point['visit'] == visits[pc], 'stack-flow instruction visit count differs')
            if pc == label['live']:
                current = seed + definitions if name == 'flow_redefine' else seed
                definitions += 1
            if pc == label.get('changed'):
                current ^= 90
            if pc == label['retired']:
                retired = True
            require(point['logical'] == current, 'stack-flow logical value differs from fixture')
            require(isinstance(point.get('bytes'), str) and re.fullmatch('(?:[0-9a-f]{2})+', point['bytes']),
                'stack-flow lacks decoded instruction bytes')
            if mode == 'forge':
                instructions = evidence['prepared'][name + '_instructions']
                saved = [row for row in instructions if row['address'] == pc]
                require(len(saved) == 1 and saved[0]['bytes'] == point['bytes']
                    and saved[0]['next'] == pc + len(point['bytes']) // 2,
                    'stack-flow instruction differs from saved program')
                require(any(low <= pc < high for low, high in evidence['prepared'][name + '_body']),
                    'stack-flow instruction outside saved body')
                matches = [row for row in evidence['locations'][name] if row['start'] <= pc < row['end']]
                available = point.get('available')
                require(type(available) is bool and len(matches) == int(available),
                    'stack-flow location availability differs from emitted ranges')
                if available:
                    require(definitions > 0 and not retired and point.get('value') == str(current)
                        and type(point.get('locationValue')) is int and point['locationValue'] == current,
                        'stack-flow exposed stale or incorrect physical value')
                else:
                    require(point.get('value') == '<optimized out>' and 'locationValue' not in point,
                        'stack-flow unavailable variable gained a value')
                if pc == label['live']:
                    require(available, 'stack-flow initial definition unavailable')
                    if name == 'flow_redefine':
                        old = seed + definitions - 2 if definitions > 1 else -23456
                        require(matches[0]['kind'] == 'stack' and point.get('staleBackup') == old
                            and old != current, 'stack-flow redefinition reused stale register')
                if pc == label['join']:
                    require(available == (name in ('flow_diamond', 'flow_loop', 'flow_redefine', 'flow_split')),
                        'stack-flow join availability differs')
                if pc == label.get('loop'):
                    require(available == (name == 'flow_loop'), 'stack-flow loop availability differs')
                if pc == label.get('changed'):
                    require(not available, 'stack-flow modified local remains available')
        require(len(biases) == 1 and retired and definitions == (
            choice + 2 if name == 'flow_redefine' else choice if name == 'flow_bypass' else 1),
            'stack-flow lifetime or runtime bias is incomplete')
        require(current == expected_return(name, seed, choice)
            and visits.get(label.get('loop'), 0) == (choice + 2 if 'loop' in label else 0),
            'stack-flow loop or result differs')
    return [(point['function'], point['seed'], point['choice'], point['linkPc'], point['bytes']) for point in points]


def oracle(record, evidence):
    require(record.get('suite') == 'stack-control-flow' and record.get('layer') == 'headless'
        and record.get('host') == 'posix' and evidence.get('target') == 'x86_64'
        and evidence.get('status') == 'PASS_STACK_CONTROL_FLOW_MEASUREMENT'
        and evidence.get('role') in ROLES and type(evidence.get('width')) is int
        and evidence['width'] in (32, 64) and evidence.get('previousPackageCompared') is False,
        'stack-flow measurement profile differs')
    require([row.get('label') for row in record['sessions']] == ['import', 'fixed', 'repeat'],
        'stack-flow requires all three analyzer sessions')
    require(hashes(evidence.get('harnessSha256')) and hashes(evidence.get('protected'))
        and hashes({'jar': evidence.get('jarSha256')})
        and evidence.get('jarSha256') == record.get('productionJarSha256')
        and evidence.get('validators') == ['readelf', 'llvm-dwarfdump', 'libdwarf-consumer'],
        'stack-flow lacks source, preservation or validator evidence')
    pair = evidence.get('artifactSha256')
    require(isinstance(pair, list) and len(pair) == 2
        and all(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) for value in pair),
        'stack-flow artifact pair hashes missing')
    required_sources = {'src/test/integration/' + name for name in (
        'stack-control-flow-export.py', 'stack-control-flow-gdb.py', 'stack-control-flow-gdb.sh',
        'check-stack-control-flow.py', 'check-stack-first-use.py', 'check-dwarfdump.py',
        'integration_coverage.py', 'ghidra_scripts/PrepareStackControlFlow.java')}
    require(required_sources <= evidence['harnessSha256'].keys(), 'stack-flow source inventory incomplete')
    initial = -1985229329 if evidence['width'] == 32 else -81985529216486895
    labels = evidence.get('labels', {})
    require(labels.get('order') == list(FUNCTIONS) and labels.get('width') == evidence['width'] // 8
        and labels.get('initial') == initial and set(evidence.get('locations', {})) == set(FUNCTIONS)
        and set(evidence.get('debugger', {})) == {'compiler', 'forge'}, 'stack-flow fixture or consumer incomplete')
    require(set(evidence.get('projectBackupChanges', [])) <= {'Effects.rep/idata/~index.bak', 'Effects.rep/idata/~journal.bak'},
        'stack-flow modified saved project')
    scenarios = [(seed, choice, name) for seed in (19, -19, initial) for choice in (0, 1) for name in FUNCTIONS]
    require(trace(evidence, 'compiler', scenarios) == trace(evidence, 'forge', scenarios),
        'stack-flow compiler/exported execution paths differ')
    return evidence['width'], evidence['role']


def cohort(cases):
    require(len(cases) == 6 and set(cases) == {(width, role) for width in (32, 64) for role in ROLES},
        'stack-flow coverage requires both widths in every ELF role')
