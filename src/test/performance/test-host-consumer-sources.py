#!/usr/bin/env python3
"""Prove relocated compiler source lookup and reject untrusted corpus inputs."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

SOURCE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('host_consumer', SOURCE / 'host-consumer.py')
CONSUMER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONSUMER)


def main():
    results = SOURCE.parents[2] / 'build/test-results/host-consumer-source-controls'
    results.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix='run.', dir=results))
    original = case / 'original-build'
    original.mkdir()
    corpus = case / 'corpus'
    (corpus / 'sqlite').mkdir(parents=True)
    (corpus / 'build-evidence').mkdir()
    text = '''volatile unsigned int observed_count = 100;
volatile unsigned int observed_sum = 5050;
__attribute__((noinline)) unsigned int benchmark_checkpoint(void)
{
    return observed_count + observed_sum;
}
int main(void)
{
    return benchmark_checkpoint() == 5150 ? 0 : 1;
}
'''
    (original / 'sqlite-workload.c').write_text(text)
    for name in ('sqlite3.c', 'sqlite3.h'):
        (original / name).write_text('/* Source relocation control. */\n')
    reference = case / 'compiler-reference'
    command = ['cc', '-O0', '-g', '-fno-pie', '-no-pie', str(original / 'sqlite-workload.c'),
        str(original / 'sqlite3.c'), '-o', str(reference)]
    subprocess.run(command, check=True, capture_output=True)
    (corpus / 'build-evidence/sqlite-compile.command.json').write_text(json.dumps(command))
    for path in original.iterdir():
        shutil.copy2(path, corpus / 'sqlite' / path.name)
    # The recorded absolute source paths are now genuinely unavailable.
    original.rename(case / 'unavailable-build')
    metadata = {'files': {str(path.relative_to(corpus)): CONSUMER.SUPPORT.digest(path)
        for path in corpus.rglob('*') if path.is_file()}}

    def gdb(label, commands):
        script = case / (label + '.gdb')
        script.write_text('\n'.join(['set pagination off', 'set confirm off',
            'set debuginfod enabled off', 'set disable-randomization off',
            'file ' + json.dumps(str(reference)), *commands]) + '\n')
        process = subprocess.run(['gdb-multiarch', '-nx', '-q', '-batch', '-x', script],
            cwd=case, capture_output=True, text=True, timeout=30)
        (case / (label + '.stdout')).write_text(process.stdout)
        (case / (label + '.stderr')).write_text(process.stderr)
        return process

    missing = gdb('unmapped', ['list benchmark_checkpoint'])
    assert 'No such file or directory' in missing.stdout + missing.stderr
    mapped = case / 'mapped'
    mapped.mkdir()
    sources = CONSUMER.prepare_compiler_sources({'name': 'sqlite'}, corpus, mapped, metadata)
    commands = ['set substitute-path ' + json.dumps(before) + ' ' + json.dumps(after)
        for before, after in sources['substitutions']]
    commands += ['break benchmark_checkpoint', 'run', 'python',
        'import hashlib', 'from pathlib import Path',
        'source = Path(gdb.selected_frame().find_sal().symtab.fullname()).resolve()',
        'assert source == Path(' + repr(sources['expectedBreakpointSource']) + ').resolve()',
        'assert hashlib.sha256(source.read_bytes()).hexdigest() == ' +
            repr(sources['expectedBreakpointSha256']),
        'assert int(gdb.parse_and_eval("observed_count")) == 100',
        'assert int(gdb.parse_and_eval("observed_sum")) == 5050', 'end',
        'list benchmark_checkpoint', 'continue', 'echo SOURCE_RELOCATION_PASS\\n']
    positive = gdb('mapped', commands)
    assert positive.returncode == 0 and not positive.stderr, positive.stderr
    assert 'SOURCE_RELOCATION_PASS' in positive.stdout and 'exited normally' in positive.stdout
    assert 'return observed_count + observed_sum;' in positive.stdout
    rejected = []

    def reject(label, workload, manifest):
        destination = case / label
        destination.mkdir()
        try:
            CONSUMER.prepare_compiler_sources(workload, corpus, destination, manifest)
        except (AssertionError, FileNotFoundError):
            rejected.append(label)
        else:
            raise AssertionError(label + ' was accepted')

    source = corpus / 'sqlite/sqlite-workload.c'
    source.write_text(text + '/* changed after corpus capture */\n')
    reject('changed-source', {'name': 'sqlite'}, metadata)
    source.write_text(text)
    header = corpus / 'sqlite/sqlite3.h'
    header.unlink()
    reject('missing-source', {'name': 'sqlite'}, metadata)
    outside = case / 'outside.h'
    outside.write_text('/* Source relocation control. */\n')
    header.symlink_to(outside)
    reject('escaped-source', {'name': 'sqlite'}, metadata)
    (corpus / 'sources').mkdir()
    archive = corpus / 'sources/u-boot-2025.01.tar.bz2'
    archive.write_bytes(b'not the pinned source archive')
    wrong = {'files': {'sources/u-boot-2025.01.tar.bz2': hashlib.sha256(archive.read_bytes()).hexdigest()}}
    reject('wrong-archive', {'name': 'uboot', 'sourceArchiveSha256':
        'cdef7d507c93f1bbd9f015ea9bc21fa074268481405501945abc6f854d5b686f'}, wrong)
    (case / 'result.json').write_text(json.dumps({'status': 'PASS',
        'unmappedCompilerSource': 'reproduced missing-source diagnostic',
        'relocatedSource': 'GDB path/hash/list/globals/normal exit', 'rejected': rejected}, indent=4) + '\n')
    print('host-consumer-source-controls=PASS results=' + str(case))


if __name__ == '__main__':
    main()
