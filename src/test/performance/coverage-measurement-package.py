#!/usr/bin/env python3
"""Audit coverage revision deltas and derive the explicit array-corrected measurement control."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile

TYPE_SOURCE = 'src/main/java/ghidradwarfforge/GhidraTypeGraph.java'
BASELINE_SOURCE_SHA = '294d9566bc2be167e1a362c380de555f11fc17e23333c3c9c148c7431664f40b'
CORRECTED_SOURCE_SHA = '7f3f5238927bb16822cd0ac821ea99036778d9f1300002cdea9f77c8abafc112'
TYPE_CLASSES = {'ghidradwarfforge/GhidraTypeGraph' + suffix + '.class'
    for suffix in ('', '$1', '$Extractor')}


def digest(value):
    return hashlib.sha256(value).hexdigest()


def packed(path):
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        assert len(names) == len(set(names)), 'duplicate archive member'
        return {name: archive.read(name) for name in names if not name.endswith('/')}


def manifest(module):
    result = {}
    for line in (module / 'RELEASE-SHA256SUMS').read_text(encoding='utf-8').splitlines():
        expected, name = line.split('  ', 1)
        path = (module / name).resolve(strict=True)
        assert path.is_relative_to(module.resolve()) and name not in result, name
        actual = digest(path.read_bytes())
        assert actual == expected, 'release manifest mismatch: ' + name
        result[name] = actual
    actual_names = {p.relative_to(module).as_posix() for p in module.rglob('*') if p.is_file()}
    assert actual_names == result.keys() | {'RELEASE-SHA256SUMS'}, 'unmanifested module files'
    return result


def inventory(module):
    classes = {name: value for name, value in packed(module / 'lib/GhidraDwarfForge.jar').items()
        if name.endswith('.class')}
    sources = {name.removeprefix('src/main/java/'): value
        for name, value in packed(module / 'lib/GhidraDwarfForge-src.zip').items()
        if name.startswith('src/main/java/') and name.endswith('.java')}
    assert classes and sources
    for name, value in classes.items():
        assert value[:4] == b'\xca\xfe\xba\xbe' and int.from_bytes(value[6:8], 'big') == 65, name
        assert source_for(name) in sources, 'class has no corresponding source: ' + name
    return classes, sources


def source_for(class_name):
    return class_name.removesuffix('.class').split('$', 1)[0] + '.java'


def audit_classes(baseline_classes, candidate_classes, baseline_sources, candidate_sources):
    changed_sources = {name for name in baseline_sources.keys() | candidate_sources.keys()
        if baseline_sources.get(name) != candidate_sources.get(name)}
    changed = sorted(name for name in baseline_classes.keys() & candidate_classes.keys()
        if baseline_classes[name] != candidate_classes[name])
    added = sorted(candidate_classes.keys() - baseline_classes.keys())
    removed = sorted(baseline_classes.keys() - candidate_classes.keys())
    for name in changed + added + removed:
        assert source_for(name) in changed_sources, 'unexplained bytecode drift: ' + name
    return {'changed': changed, 'added': added, 'removed': removed,
        'unchangedShared': len(baseline_classes.keys() & candidate_classes.keys()) - len(changed),
        'classMajor': 65, 'changedSources': {name: {
            'baselineSha256': digest(baseline_sources[name]) if name in baseline_sources else None,
            'candidateSha256': digest(candidate_sources[name]) if name in candidate_sources else None}
            for name in sorted(changed_sources)},
        'scope': 'Whole coverage revision comparison, not phase-hook overhead. Every bytecode delta '
            'has a changed source root; all classes from unchanged source must be byte-identical.'}


def audit(baseline, candidate):
    old_classes, old_sources = inventory(baseline)
    new_classes, new_sources = inventory(candidate)
    result = audit_classes(old_classes, new_classes, old_sources, new_sources)
    # Record native differences rather than incorrectly attributing independent
    # production rebuild effects solely to coverage Java code.
    old_manifest, new_manifest = manifest(baseline), manifest(candidate)
    result['nativeFiles'] = {name: {'baselineSha256': old_manifest.get(name),
        'candidateSha256': new_manifest.get(name)}
        for name in sorted(old_manifest.keys() | new_manifest.keys()) if name.startswith('os/')}
    return result


def rewrite_archive(path, replacements):
    temporary = path.with_suffix(path.suffix + '.control')
    with zipfile.ZipFile(path) as source, zipfile.ZipFile(temporary, 'x') as destination:
        assert replacements.keys() <= set(source.namelist())
        for entry in source.infolist():
            destination.writestr(entry, replacements.get(entry.filename, source.read(entry.filename)))
    os.replace(temporary, path)


def derive(source, candidate, ghidra, destination, evidence):
    """Create a new non-release module; never modify either production module."""
    assert not destination.exists(), 'measurement control destination already exists'
    assert all(not output.is_relative_to(original) for output in (destination, evidence)
        for original in (source, candidate)), 'control/evidence must be outside production modules'
    evidence.mkdir(parents=True, exist_ok=False)
    before = manifest(source)
    candidate_before = manifest(candidate)
    source_zip = packed(source / 'lib/GhidraDwarfForge-src.zip')
    current_zip = packed(candidate / 'lib/GhidraDwarfForge-src.zip')
    old = source_zip[TYPE_SOURCE]
    corrected = current_zip[TYPE_SOURCE]
    assert digest(old) == BASELINE_SOURCE_SHA, 'unexpected pinned baseline source'
    assert digest(corrected) == CORRECTED_SOURCE_SHA, 'unexpected array correction'
    # The exact reviewed source hashes bound the correction independently of
    # candidate checkout contents. Retain both source versions for inspection.
    (evidence / 'GhidraTypeGraph.before.java').write_bytes(old)
    (evidence / 'GhidraTypeGraph.java').write_bytes(corrected)
    classes = evidence / 'classes'
    classes.mkdir()
    jars = [source / 'lib/GhidraDwarfForge.jar']
    for parent, directories, files in os.walk(ghidra / 'Ghidra', followlinks=True):
        directories[:] = sorted(name for name in directories if name not in ('Extensions', 'data'))
        jars.extend(Path(parent) / name for name in sorted(files) if name.endswith('.jar'))
    javac = Path(os.environ['JAVA_HOME']) / 'bin' / ('javac.exe' if os.name == 'nt' else 'javac')
    version = subprocess.check_output([str(javac), '-version'], stderr=subprocess.STDOUT, text=True).strip()
    assert version.startswith('javac 21.'), version
    args = ['-g', '--release', '21', '-encoding', 'UTF-8', '-cp', os.pathsep.join(map(str, jars)),
        '-d', str(classes), str(evidence / 'GhidraTypeGraph.java')]
    argfile = evidence / 'javac.args'
    argfile.write_text('\n'.join('"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'
        for value in args) + '\n', encoding='utf-8')
    with (evidence / 'compile.log').open('w', encoding='utf-8') as log:
        subprocess.run([str(javac), '@' + str(argfile)], stdout=log, stderr=subprocess.STDOUT,
            check=True, timeout=180)
    replacements = {p.relative_to(classes).as_posix(): p.read_bytes() for p in classes.rglob('*.class')}
    assert replacements.keys() == TYPE_CLASSES, 'unexpected correction class population'
    candidate_classes, _ = inventory(candidate)
    assert all(candidate_classes[name] == value for name, value in replacements.items()), \
        'isolated compiler output differs from actual candidate class bytes'
    # Private staging prevents publishing a partially constructed control.
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='forge-control-', dir=destination.parent) as temporary:
        stage = Path(temporary) / 'GhidraDwarfForge'
        shutil.copytree(source, stage)
        rewrite_archive(stage / 'lib/GhidraDwarfForge.jar', replacements)
        rewrite_archive(stage / 'lib/GhidraDwarfForge-src.zip', {TYPE_SOURCE: corrected})
        after = {p.relative_to(stage).as_posix(): digest(p.read_bytes()) for p in stage.rglob('*')
            if p.is_file() and p.name != 'RELEASE-SHA256SUMS'}
        assert before.keys() == after.keys()
        assert {name for name in before if before[name] != after[name]} == {
            'lib/GhidraDwarfForge.jar', 'lib/GhidraDwarfForge-src.zip'}
        old_jar = packed(source / 'lib/GhidraDwarfForge.jar')
        new_jar = packed(stage / 'lib/GhidraDwarfForge.jar')
        assert old_jar.keys() == new_jar.keys()
        assert {name for name in old_jar if old_jar[name] != new_jar[name]} <= TYPE_CLASSES
        (stage / 'RELEASE-SHA256SUMS').write_text(''.join(value + '  ' + name + '\n'
            for name, value in sorted(after.items())), encoding='utf-8')
        assert manifest(source) == before and manifest(candidate) == candidate_before
        manifest(stage)
        receipt = {'status': 'PASS', 'scope': 'Measurement-only baseline control; not a production release.',
            'baselineCommit': '1bb4c14c550d277817315cf0ed97853a949e1e03',
            'sourceModule': str(source), 'candidateModule': str(candidate), 'controlModule': str(destination),
            'javac': version, 'originalFiles': before, 'controlFiles': after,
            'baselineSourceSha256': digest(old), 'correctedSourceSha256': digest(corrected),
            'correctedClasses': {name: digest(value) for name, value in sorted(replacements.items())},
            'compiledClassesMatchCandidate': True, 'productionInputsUnchanged': True}
        (evidence / 'receipt.json').write_text(json.dumps(receipt, indent=4) + '\n', encoding='utf-8')
        stage.rename(destination)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('candidate', type=Path)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('destination', type=Path)
    parser.add_argument('evidence', type=Path)
    args = parser.parse_args()
    derive(*(path.resolve() for path in (args.source, args.candidate, args.ghidra,
        args.destination, args.evidence)))
    print('coverage-measurement-control=PASS ' + str(args.evidence))


if __name__ == '__main__':
    main()
