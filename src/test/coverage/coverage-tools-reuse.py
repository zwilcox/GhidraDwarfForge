#!/usr/bin/env python3
"""Exercise real offline Gradle tool preparation and reject altered CI bundles."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile


REPO = Path(__file__).resolve().parents[3]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    bundle = args.bundle.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    manifest = json.loads((bundle / 'collection/manifest.json').read_text())
    metadata = json.loads((bundle / 'tools.json').read_text())
    environment = dict(os.environ, GITHUB_SHA=manifest['commit'],
        FORGE_COVERAGE_RUN_ID=manifest['run'], FORGE_COVERAGE_TOOLS_BUNDLE=str(bundle))
    gradle = REPO / ('gradlew.bat' if os.name == 'nt' else 'gradlew')
    command = [str(gradle), '--no-daemon', '--offline', '-PtestCoverage=true']

    def run(label, root, task, reason=None, **overrides):
        env = dict(environment, FORGE_COVERAGE_TOOLS_BUNDLE=str(root))
        env.update(overrides)
        with (output / (label + '.log')).open('w') as log:
            result = subprocess.run(command + [task], cwd=REPO, env=env,
                stdout=log, stderr=subprocess.STDOUT, timeout=180)
        text = (output / (label + '.log')).read_text()
        if reason is None:
            if result.returncode != 0 or 'BUILD SUCCESSFUL' not in text:
                raise AssertionError('offline preparation failed: ' + label)
        elif result.returncode == 0 or reason not in text:
            raise AssertionError('missing expected refusal: ' + label)

    run('offline-preparation', bundle, 'prepareIntegrationCoverage')
    prepared = REPO / 'build/test-coverage-tools'
    expected = {name: digest(bundle / 'tools' / name) for name in metadata['files']}
    if {p.name: digest(p) for p in (prepared / 'report-libs').iterdir()} != expected:
        raise AssertionError('prepared report dependencies differ')
    paths = (prepared / 'jacoco-classpath.txt').read_text().strip().split(os.pathsep)
    if {Path(p).resolve() for p in paths} != {(bundle / 'tools' / name).resolve() for name in expected}:
        raise AssertionError('report classpath did not use the bundle')
    with zipfile.ZipFile(bundle / 'tools/org.jacoco.agent-0.8.16.jar') as archive:
        if (prepared / 'jacocoagent.jar').read_bytes() != archive.read('jacocoagent.jar'):
            raise AssertionError('prepared instrumentation agent differs')
    snapshot = {p.relative_to(prepared).as_posix(): digest(p)
        for p in prepared.rglob('*') if p.is_file()}
    for case in ('commit', 'run', 'version', 'extra', 'missing', 'changed', 'agent'):
        with tempfile.TemporaryDirectory(prefix='coverage-tools-') as temporary:
            root = Path(temporary)
            (root / 'collection').mkdir()
            shutil.copyfile(bundle / 'collection/manifest.json', root / 'collection/manifest.json')
            shutil.copytree(bundle / 'tools', root / 'tools')
            record = json.loads((bundle / 'tools.json').read_text())
            env = {}
            reason = 'Coverage tools must come from the same commit/run and JaCoCo version'
            name = 'org.jacoco.agent-0.8.16.jar'
            if case == 'commit':
                env['GITHUB_SHA'] = '0' * 40
            elif case == 'run':
                env['FORGE_COVERAGE_RUN_ID'] = 'different-run'
            elif case == 'version':
                record['jacocoVersion'] = '0.0.0'
            elif case == 'extra':
                (root / 'tools/unrecorded.jar').write_bytes(b'unrecorded')
                reason = 'Missing or unrecorded coverage tool files'
            elif case in ('missing', 'agent'):
                (root / 'tools' / name).unlink()
                reason = 'Missing or unrecorded coverage tool files'
                if case == 'agent':
                    del record['files'][name]
                    reason = 'Missing coverage agent dependency'
            elif case == 'changed':
                (root / 'tools' / name).write_bytes(b'changed dependency')
                reason = 'Changed coverage tool'
            (root / 'tools.json').write_text(json.dumps(record))
            run(case, root, 'help', reason, **env)
        if snapshot != {p.relative_to(prepared).as_posix(): digest(p)
                for p in prepared.rglob('*') if p.is_file()}:
            raise AssertionError('refused bundle changed prepared tools: ' + case)
    result = {'status': 'PASS', 'offlinePreparation': True, 'refusalControls': 7,
        'scope': 'Tool reuse and input rejection; not architecture or coverage acceptance'}
    (output / 'result.json').write_text(json.dumps(result, indent=4) + '\n')
    print('coverage-tools-reuse=PASS refusal-controls=7 offline=true')


if __name__ == '__main__':
    main()
