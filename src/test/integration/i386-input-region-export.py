#!/usr/bin/env python3
"""Compiler/GDB regression for i386 x87 returns at the finite compiler input-region boundary."""
from pathlib import Path
import hashlib
import json
import os
import signal
import subprocess
import time
import argparse
import re
import struct
import textwrap
from urllib.parse import unquote, urlsplit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('--results', type=Path, required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[3]
    root = args.results.resolve()
    root.mkdir(parents=True, exist_ok=False)
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    installed = module
    scripts = repo / 'src/test/integration/ghidra_scripts'
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    before_module = {str(p.relative_to(installed)): digest(p) for p in installed.rglob('*') if p.is_file()}
    env = dict(os.environ)
    if any(char.isspace() for char in str(root)):
        raise ValueError('this headless fixture requires a results path without whitespace')
    env['JAVA_TOOL_OPTIONS'] = env.get('JAVA_TOOL_OPTIONS', '') + ' -Dapplication.cachedir=' + str(root / 'cache') + ' -Dapplication.settingsdir=' + str(root / 'settings')
    observations = []

    def run(case, label, command, timeout=240):
        command = list(map(str, command))
        (case / (label + '-command.json')).write_text(json.dumps(command, indent=4) + '\n')
        path = case / (label + '.log')
        start = time.monotonic()
        with path.open('w') as log:
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, env=env, start_new_session=True)
            try:
                while process.poll() is None:
                    if time.monotonic() - start > timeout or path.stat().st_size > 8 * 1024 * 1024:
                        raise RuntimeError('process exceeded time/output bound: ' + label)
                    time.sleep(.1)
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    try: process.wait(timeout=3)
                    except subprocess.TimeoutExpired: pass
                    try: os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    process.wait()
        if process.returncode:
            raise RuntimeError(f'{label} failed with {process.returncode}; see {path}')
        return path.read_text()

    for role, count in ((role, count) for role in ('exec', 'pie') for count in (124, 125, 126)):
        case = root / (role + '-' + str(count))
        case.mkdir()
        project = case / 'project'
        project.mkdir()
        arguments = ', '.join('int a' + str(i) for i in range(count))
        values = ', '.join(str(i + 1) for i in range(count))
        source = case / 'limit.c'
        source.write_text(textwrap.dedent(f"""
            __attribute__((noinline)) int ordinary(void) {{ return 7; }}
            __attribute__((noinline)) long double big({arguments}) {{ return (long double)a0 + a{count - 1}; }}
            __attribute__((noreturn)) void _start(void) {{
                long double result = big({values}) + ordinary();
                int status = result == {count + 8}.0L ? 0 : 1;
                __asm__ volatile("int $0x80" : : "a"(1), "b"(status) : "memory");
                __builtin_unreachable();
            }}
        """))
        reference, binary = case / 'reference', case / 'input'
        flags = ['-fno-pie', '-no-pie', '-static'] if role == 'exec' else ['-fPIE', '-static-pie']
        run(case, 'compile', ['gcc', '-m32', '-O0', '-g', '-gdwarf-5', '-fno-stack-protector',
            *flags, '-nostdlib', '-Wl,--build-id=sha1', '-Wl,-e,_start', source, '-o', reference])
        header = reference.read_bytes()[:52]
        assert header[:6] == b'\x7fELF\x01\x01' and struct.unpack_from('<H', header, 16)[0] == (2 if role == 'exec' else 3)
        run(case, 'compiler-runtime', [reference], timeout=10)
        run(case, 'strip-debug', ['objcopy', '--strip-debug', reference, binary])
        run(case, 'input-runtime', [binary], timeout=10)
        original_hash = digest(binary)
        log = run(case, 'import', [ghidra / 'support/analyzeHeadless', project, 'Limit', '-import', binary,
            '-loader', 'ElfLoader', '-analysisTimeoutPerFile', '90', '-scriptPath', scripts,
            '-postScript', 'PrepareI386InputRegion.java', 'curate', count, case / 'model-before.json'])
        assert 'i386-limit-model=PASS' in log and 'REPORT: Analysis succeeded' in log
        imported = json.loads((case / 'model-before.json').read_text())
        assert Path(unquote(urlsplit(imported['origin']).path)).resolve() == (installed / 'lib/GhidraDwarfForge.jar').resolve()
        sidecar, source_output = case / 'profile.dbg', case / 'profile.dbg.c'
        sidecar.write_bytes(b'previous sidecar must survive failure\n')
        source_output.write_bytes(b'previous source must survive failure\n')
        prior = [digest(sidecar), digest(source_output)]
        before_project = {str(p.relative_to(project)): digest(p) for p in project.rglob('*') if p.is_file()}
        log = run(case, 'export', [ghidra / 'support/analyzeHeadless', project, 'Limit', '-process', binary.name,
            '-readOnly', '-noanalysis', '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(sidecar)])
        exported = 'GhidraDwarfForge symbol export PASS' in log
        observation = {'role': role, 'count': count, 'exported': exported, 'originalUnchanged': digest(binary) == original_hash,
            'priorOutputsPreserved': [digest(sidecar), digest(source_output)] == prior,
            'allocationDiagnostic': 'Floating-return correction escaped audited stack boundary' in log,
            'productionJarSha256': digest(installed / 'lib/GhidraDwarfForge.jar')}
        assert observation['originalUnchanged'] and exported and not observation['allocationDiagnostic']
        assert 'Unexpected Exception' not in log
        report_text = log.split('GhidraDwarfForge report: ', 1)[1]
        report, _ = json.JSONDecoder().raw_decode(report_text)
        assert report['counts']['functionsFailed'] == 0 and not report['failedFunctions']
        observation['functionsExported'] = report['counts']['functionsExported']
        assert observation['functionsExported'] >= 3
        pair = [digest(sidecar), digest(source_output)]
        repeat = run(case, 'repeat', [ghidra / 'support/analyzeHeadless', project, 'Limit', '-process', binary.name,
            '-readOnly', '-noanalysis', '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(sidecar)])
        assert 'GhidraDwarfForge symbol export PASS' in repeat and 'Unexpected Exception' not in repeat
        assert [digest(sidecar), digest(source_output)] == pair
        observation['deterministicPair'] = True
        observe = run(case, 'observe', [ghidra / 'support/analyzeHeadless', project, 'Limit', '-process', binary.name,
            '-readOnly', '-noanalysis', '-scriptPath', scripts, '-postScript', 'PrepareI386InputRegion.java', 'observe', count,
            case / 'model-after.json'])
        assert 'i386-limit-model=PASS' in observe
        observation['modelUnchanged'] = json.loads((case / 'model-before.json').read_text()) == json.loads((case / 'model-after.json').read_text())
        assert observation['modelUnchanged']
        after_project = {str(p.relative_to(project)): digest(p) for p in project.rglob('*') if p.is_file()}
        changes = sorted(p for p in before_project.keys() | after_project.keys() if before_project.get(p) != after_project.get(p))
        observation['projectChanges'] = changes
        assert set(changes) <= {'Limit.rep/idata/~index.bak', 'Limit.rep/idata/~journal.bak'}, changes
        (case / 'observation.json').write_text(json.dumps(observation, indent=4) + '\n')
        observations.append(observation)
        if exported:
            for label, command in [('header', ['readelf', '-h', sidecar]), ('sections', ['readelf', '-SW', sidecar]),
                    ('info', ['readelf', '--debug-dump=info', sidecar]), ('abbrev', ['readelf', '--debug-dump=abbrev', sidecar]),
                    ('lines', ['readelf', '--debug-dump=decodedline', sidecar]), ('ranges', ['readelf', '--debug-dump=aranges', sidecar]), ('llvm', ['llvm-dwarfdump', '--verify', sidecar]),
                    ('strict', ['python3', repo / 'src/test/integration/check-dwarfdump.py', sidecar, case / 'strict.txt', '--original', binary])]:
                text = run(case, label, command)
                assert not re.search(r'(?im)\b(?:warning|error):', text), (label, text[:1000])
            for label, symbols, allow_missing in [('compiler-gdb', reference, False), ('forge-gdb', sidecar, count > 125)]:
                gdb_script = case / (label + '.gdb')
                gdb_script.write_text(textwrap.dedent(f"""
                    set pagination off
                    set debuginfod enabled off
                    set confirm off
                    file {binary}
                    set auto-solib-add off
                    symbol-file {symbols}
                    break big
                    run
                    python
                    assert int(gdb.parse_and_eval("a0")) == 1
                    last = gdb.parse_and_eval("a{count - 1}")
                    assert last.is_optimized_out if {allow_missing} else int(last) == {count}
                    if {count} > 125:
                        assert int(gdb.parse_and_eval("a124")) == 125
                    print("last-argument-unavailable=" + str(last.is_optimized_out))
                    print("i386-limit-gdb=PASS")
                    end
                    list big
                    finish
                    break ordinary
                    continue
                    python
                    assert gdb.selected_frame().name() == "ordinary"
                    print("ordinary-function-preserved=PASS")
                    end
                    finish
                    continue
                """))
                gdb = run(case, label, ['gdb', '-q', '-nx', '-batch', '-x', gdb_script])
                assert 'i386-limit-gdb=PASS' in gdb and 'ordinary-function-preserved=PASS' in gdb and 'exited normally' in gdb
                assert 'No such file or directory' not in gdb and 'No source file' not in gdb
            observation['validatorsAndGdb'] = 'PASS'
        assert digest(binary) == original_hash
        (case / 'observation.json').write_text(json.dumps(observation, indent=4) + '\n')
        print(json.dumps(observation), flush=True)
    assert all(case['exported'] for case in observations)
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_I386_INPUT_REGION_FIX', 'cases': observations,
        'coverageAdmission': False, 'productionJarSha256': digest(installed / 'lib/GhidraDwarfForge.jar')}, indent=4) + '\n')
    assert {str(p.relative_to(installed)): digest(p) for p in installed.rglob('*') if p.is_file()} == before_module
    print('i386-input-region-export=PASS cases=6', flush=True)


if __name__ == "__main__":
    main()
