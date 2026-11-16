#!/usr/bin/env python3
"""Measure added/modified executable Java lines against an explicit ancestor.

Pure renames and deleted lines add no executable scope. All branches on each
changed line count, including those in partially covered expressions. Exception
handling requires behavioral review because JaCoCo does not count catch edges.
"""
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
import re
import subprocess
import xml.etree.ElementTree as ET


PREFIX = 'src/main/java/'
TARGETS = {'line': 90, 'branchMinimum': 85, 'branchPreferred': 90}


def git(repository, *arguments):
    result = subprocess.run(['git', '--no-replace-objects', '--literal-pathspecs', *arguments],
        cwd=repository, capture_output=True, timeout=30)
    if result.returncode or len(result.stdout) > 16 * 1024 * 1024:
        raise ValueError('unavailable or excessive coverage comparison history')
    return result.stdout


def changed_lines(repository, base, commit):
    if any(not re.fullmatch(r'[0-9a-f]{40}', value) for value in (base, commit)):
        raise ValueError('coverage comparison requires full base and source commits')
    if git(repository, 'rev-parse', 'HEAD').decode().strip() != commit:
        raise ValueError('coverage comparison checkout differs from source commit')
    git(repository, 'merge-base', '--is-ancestor', base, commit)
    git(repository, 'diff', '--quiet', commit, '--', PREFIX)
    if git(repository, 'ls-files', '--others', '--exclude-standard', '--', PREFIX):
        raise ValueError('uncommitted production source in coverage comparison')
    tokens = git(repository, 'diff', '--no-ext-diff', '--no-textconv', '--name-status',
        '-z', '--find-renames=100%', base, commit, '--', PREFIX).decode().split('\0')
    if tokens.pop() != '':
        raise ValueError('incomplete changed-source inventory')
    changed, renames = {}, []
    while tokens:
        status, name = tokens.pop(0), tokens.pop(0)
        if status == 'D':
            continue
        if status == 'R100':
            renames.append({'from': name, 'to': tokens.pop(0)})
            continue
        if status not in ('A', 'M', 'T'):
            raise ValueError('unsupported production source change: ' + status)
        if not name.endswith('.java'):
            continue
        if (not name.startswith(PREFIX) or any(part in ('.', '..') for part in Path(name).parts)
                or any(character in name for character in '\t\r\n')):
            raise ValueError('invalid changed production source path')
        tree = git(repository, 'ls-tree', commit, '--', name).decode()
        if not tree.startswith(('100644 blob ', '100755 blob ')):
            raise ValueError('changed source is not a regular committed file')
        patch = git(repository, 'diff', '--no-ext-diff', '--no-textconv', '--no-color',
            '--unified=0', base, commit, '--', name).decode()
        lines = set()
        for match in re.finditer(r'^@@ -[0-9]+(?:,[0-9]+)? \+([0-9]+)(?:,([0-9]+))? @@', patch, re.M):
            start = int(match[1])
            count = 1 if match[2] is None else int(match[2])
            lines.update(range(start, start + count))
        changed[name[len(PREFIX):]] = lines
    return changed, renames


def line_inventory(xml):
    if xml.is_symlink() or not xml.is_file() or xml.stat().st_size > 32 * 1024 * 1024:
        raise ValueError('invalid changed-code XML report')
    sources = {}
    for package in ET.parse(xml).getroot().findall('package'):
        for source in package.findall('sourcefile'):
            name = package.get('name', '') + '/' + source.get('name', '')
            if name in sources:
                raise ValueError('duplicate changed-code source')
            lines = {}
            for row in source.findall('line'):
                values = [row.get(key, '') for key in ('nr', 'mi', 'ci', 'mb', 'cb')]
                if any(not re.fullmatch(r'0|[1-9][0-9]{0,9}', value) for value in values):
                    raise ValueError('invalid changed-code line counters')
                number, mi, ci, mb, cb = map(int, values)
                if number == 0 or number in lines or (mi + ci == 0 and mb + cb != 0):
                    raise ValueError('duplicate or inconsistent changed-code line counters')
                lines[number] = (mi, ci, mb, cb)
            sources[name] = lines
    return sources


def metric(covered, missed, target):
    total = covered + missed
    return {'covered': covered, 'missed': missed, 'target': target,
        'percent': None if total == 0 else str((Decimal(100) * covered / total).quantize(
            Decimal('0.1'), rounding=ROUND_HALF_UP)),
        'targetMet': None if total == 0 else 100 * covered >= target * total}


def report(repository, base, commit, xml, targets):
    if targets != TARGETS:
        raise ValueError('changed-code targets differ from the accepted milestone')
    changes, renames = changed_lines(repository, base, commit)
    measured = line_inventory(xml)
    files = {}
    totals = [0, 0, 0, 0]
    for name, numbers in sorted(changes.items()):
        if name not in measured:
            raise ValueError('changed production source missing from measurement: ' + name)
        covered, missed, branches, missed_branches = 0, 0, 0, 0
        uncovered, partial, executable = [], [], []
        for number in sorted(numbers):
            mi, ci, mb, cb = measured[name].get(number, (0, 0, 0, 0))
            if mi + ci == 0:
                continue
            executable.append(number)
            covered += int(ci > 0)
            missed += int(ci == 0)
            branches += cb
            missed_branches += mb
            if ci == 0:
                uncovered.append(number)
            if mb:
                partial.append(number)
        files[name] = {'changedLines': sorted(numbers), 'executableLines': executable,
            'uncoveredLines': uncovered, 'linesWithUncoveredBranches': partial,
            'LINE': metric(covered, missed, targets['line']),
            'BRANCH': metric(branches, missed_branches, targets['branchMinimum'])}
        totals = [a + b for a, b in zip(totals, (covered, missed, branches, missed_branches))]
    line = metric(*totals[:2], targets['line'])
    branch = metric(*totals[2:], targets['branchMinimum'])
    return {'schema': 1, 'baseCommit': base, 'commit': commit,
        'scope': 'Added or modified executable production Java lines; all branches on those lines',
        'exceptionHandling': 'JaCoCo excludes catch edges; review failure and recovery assertions separately',
        'files': files, 'pureRenames': renames, 'LINE': line, 'BRANCH': branch,
        'preferredBranchTarget': targets['branchPreferred'],
        'preferredBranchTargetMet': metric(*totals[2:], targets['branchPreferred'])['targetMet'],
        'targetsMet': line['targetMet'] is not False and branch['targetMet'] is not False,
        'status': 'NOT_APPLICABLE' if sum(totals) == 0 else 'MEASURED'}
