#!/usr/bin/env python3
"""Exercise the packaged read-only CLI with real reports and explicit report-only mutations."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def require(value, message):
    if not value:
        raise AssertionError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('module', type=Path)
    parser.add_argument('report', type=Path)
    args = parser.parse_args()
    ghidra, module, report = (p.resolve() for p in (args.ghidra, args.module, args.report))
    original = json.loads(report.read_text(encoding='utf-8'))
    require(original['schemaVersion'] == 2, 'fixture needs actual production schema two')
    root = Path(__file__).resolve().parents[3] / 'build/test-results/coverage-report-tool'
    root.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='run.', dir=root))
    selected = work / 'literal $(touch PWNED) ; [x] λ 🛠.json'
    selected.write_bytes(report.read_bytes())
    java = os.environ.get('JAVA_BIN')
    if not java and os.environ.get('JAVA_HOME'):
        java = str(Path(os.environ['JAVA_HOME']) / 'bin' / ('java.exe' if os.name == 'nt' else 'java'))
    java = java or shutil.which('java')
    require(java, 'Java executable missing')
    if os.name == 'nt':
        shell = shutil.which('pwsh')
        require(shell, 'PowerShell 7 required for the Windows launcher')
        prefix = [shell, '-NoProfile', '-File', str(module / 'support/ghidra-dwarf-forge-report.ps1'),
                  '-GhidraDirectory', str(ghidra), '-ExtensionDirectory', str(module), '-JavaExecutable', java]
        report_option, before_option, summary_option, function_option = '-ReportFile', '-BeforeFile', '-Summary', '-Function'
    else:
        prefix = [str(module / 'support/ghidra-dwarf-forge-report'), '--ghidra-dir=' + str(ghidra),
                  '--extension-dir=' + str(module), '--java=' + java]
        report_option, before_option, summary_option, function_option = '--report', '--before', '--summary', '--function'
    protected = [report, selected, module / 'lib/GhidraDwarfForge.jar', module / 'support/ghidra-dwarf-forge-report',
                 module / 'support/ghidra-dwarf-forge-report.ps1']
    protected.extend(Path(original['artifacts'][key]) for key in ('inputPath', 'outputPath', 'sourcePath')
                     if Path(original['artifacts'][key]).is_file())
    hashes = {str(path): sha(path) for path in protected}
    cases = []

    def option(name, value):
        return [name, str(value)] if os.name == 'nt' else [name + '=' + str(value)]

    def run(name, path, extra=(), expected=0):
        command = prefix + option(report_option, path) + list(extra)
        result = subprocess.run(command, cwd=work, capture_output=True, encoding='utf-8', timeout=90)
        (work / (name + '.stdout.txt')).write_text(result.stdout, encoding='utf-8')
        (work / (name + '.stderr.txt')).write_text(result.stderr, encoding='utf-8')
        require(result.returncode == expected, f'{name}: {result.returncode}: {result.stderr[:1000]}')
        if expected in (0, 2):
            require(not result.stderr, f'{name}: unexpected stderr: {result.stderr[:1000]}')
        require(not (work / 'PWNED').exists(), 'literal path was evaluated by a shell')
        cases.append({'name': name, 'status': result.returncode, 'command': command})
        return result.stdout

    text = run('show', selected)
    require('Function\tELF entry\tSource' in text, 'per-function TSV absent')
    require('not execution coverage' in text and 'no referenced artifact' in text, 'meaning/authority limits missing')
    run('summary', selected, [summary_option])
    first = original['coverage']['functions'][0]
    detail = run('detail', selected, option(function_option, first['entry']))
    require('Signature provenance:' in detail and 'Token anchors:' in detail, 'selected function evidence absent')
    unchanged = run('same', selected, option(before_option, selected))
    require('Reported changes: 0;' in unchanged and 'not an exhaustive semantic equivalence' in unchanged, 'identical report/limits mismatch')
    moved = copy.deepcopy(original)
    for key in ('inputPath', 'outputPath', 'sourcePath'):
        moved['artifacts'][key] = str(work / ('deliberately-missing-' + key))
    moved_path = work / 'moved.json'
    moved_path.write_text(json.dumps(moved), encoding='utf-8')
    require('Reported changes: 0;' in run('moved', moved_path, option(before_option, selected)), 'path-only move changed comparison')
    changed = copy.deepcopy(moved)
    function = next(f for f in changed['coverage']['functions'] if f['source']['anchoredStarts'] and
                    set(f['source']['lineVisibleStarts']) - set(f['source']['anchoredStarts']))
    source = function['source']
    lost = source['anchoredStarts'][0]
    gained = min(set(source['lineVisibleStarts']) - set(source['anchoredStarts']), key=lambda a: int(a, 16))
    source['anchoredStarts'] = sorted((set(source['anchoredStarts']) - {lost}) | {gained}, key=lambda a: int(a, 16))
    function['name'] += ' renamed'
    union = {point for f in changed['coverage']['functions'] for point in (f['source']['anchoredStarts'] or [])}
    changed['coverage']['summary']['source']['anchoredInstructions'] = str(len(union))
    changed_path = work / 'changed.json'
    changed_path.write_text(json.dumps(changed), encoding='utf-8')
    comparison = run('changed', changed_path, option(before_option, selected))
    require(f"ANCHOR_LOST\t{function['entry']}\t{lost}" in comparison, 'equal-count anchor loss hidden')
    require(f"ANCHOR_GAINED\t{function['entry']}\t{gained}" in comparison and 'FUNCTION_RENAMED' in comparison, 'anchor gain/rename missing')
    changed['artifacts']['inputSha256'] = '0' * 64
    changed_path.write_text(json.dumps(changed), encoding='utf-8')
    require('INCOMPARABLE' in run('different-input', changed_path, option(before_option, selected), 2), 'input mismatch accepted')
    legacy = copy.deepcopy(original)
    legacy['schemaVersion'] = 1
    del legacy['coverage']
    legacy_path = work / 'legacy.json'
    legacy_path.write_text(json.dumps(legacy), encoding='utf-8')
    require('UNAVAILABLE (schema one)' in run('legacy', legacy_path), 'legacy coverage invented')
    run('legacy-compare', selected, option(before_option, legacy_path), 2)
    malformed = work / 'malformed.json'
    malformed.write_text('{', encoding='utf-8')
    run('malformed', malformed, expected=1)
    require(hashes == {str(path): sha(path) for path in protected}, 'CLI changed selected reports/artifacts/module')
    result = {'status': 'PASS', 'scope': 'packaged CLI on actual report plus report-only mutation controls; no new exported regression artifact',
              'host': os.name, 'protectedSha256': hashes, 'cases': cases, 'report': str(report)}
    (work / 'result.json').write_text(json.dumps(result, indent=4) + '\n', encoding='utf-8')
    print('coverage-report-tool=PASS results=' + str(work))


if __name__ == '__main__':
    main()
