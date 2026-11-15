"""Opt-in per-JVM coverage for existing integration oracles; never a process launcher.

Harnesses still own their subprocesses, timeouts, cleanup and behavioral checks.
A session is accepted only when that oracle returns normally and the complete
harness subsequently binds its PASS receipt. JaCoCo bytecode verification and
report generation are separate prerequisites to accepting coverage counters.
"""
from contextlib import contextmanager
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import uuid
from zipfile import ZipFile


MAX_EXEC_BYTES = 16 * 1024 * 1024
MAX_RUN_BYTES = 64 * 1024 * 1024
MAX_SESSIONS = 2048


def passing_status(value):
    return isinstance(value, str) and re.fullmatch(r'PASS(?:_[A-Z0-9]+)*', value) is not None


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=4) + '\n', encoding='utf-8')


class Collection:
    def __init__(self, suite, jar, layer, *, test_classes=(), environment=None):
        environment = os.environ if environment is None else environment
        output = environment.get('FORGE_INTEGRATION_COVERAGE_OUTPUT')
        agent = environment.get('FORGE_INTEGRATION_COVERAGE_AGENT')
        if bool(output) != bool(agent):
            raise ValueError('integration coverage requires both output and agent')
        self.enabled = bool(output)
        self.closed = False
        if not self.enabled:
            return
        if not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', suite):
            raise ValueError('invalid coverage suite name')
        if layer not in ('native-java', 'headless', 'windows'):
            raise ValueError('invalid integration coverage layer')
        if any(not re.fullmatch(r'ghidradwarfforge\.[A-Za-z0-9_.]+', name) for name in test_classes):
            raise ValueError('test exclusions must name explicit test classes')
        excludes = tuple(pattern for name in test_classes for pattern in (name, name + '$*'))
        self.jar = Path(jar).resolve(strict=True)
        self.agent = Path(agent).resolve(strict=True)
        parent = Path(output).resolve()
        # A direct java argv supports spaces; JaCoCo option separators do not.
        if any(re.search(r'[,=\r\n]', str(path)) for path in (parent, self.agent)):
            raise ValueError('coverage paths must not contain JaCoCo option separators')
        with ZipFile(self.jar) as archive:
            classes = [name[:-6].replace('/', '.') for name in archive.namelist()
                if name.endswith('.class')]
        if not classes or any(not name.startswith('ghidradwarfforge.') for name in classes):
            raise ValueError('unexpected production JAR population')
        if any(fnmatch.fnmatchcase(name, pattern) for name in classes for pattern in excludes):
            raise ValueError('test exclusions would remove a production class')
        parent.mkdir(parents=True, exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix=suite + '-', dir=parent))
        self.record = {'schema': 1, 'status': 'INCOMPLETE', 'suite': suite,
            'layer': layer, 'host': os.name, 'productionJarSha256': digest(self.jar),
            'agentSha256': digest(self.agent), 'productionClasses': len(classes),
            'excludes': list(excludes), 'sessions': [], 'unmeasuredForcedHalts': []}
        self._save()

    def _save(self):
        save(self.root / 'receipt.json', self.record)

    @contextmanager
    def session(self, command, label, *, headless=False):
        """Wrap a direct JVM or the pinned Linux Ghidra headless launcher and its oracle."""
        if not self.enabled:
            yield command
            return
        if self.closed:
            raise ValueError('coverage collection already finished')
        command = list(map(str, command))
        if headless:
            if (os.name != 'posix' or self.record['layer'] != 'headless' or not command
                    or Path(command[0]).name != 'analyzeHeadless'):
                raise ValueError('headless collection requires the Linux Ghidra launcher')
            launcher = Path(command[0]).resolve(strict=True)
            installed = launcher.parent.parent / 'Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar'
            if installed.resolve(strict=True) != self.jar:
                raise ValueError('headless launcher does not use the measured installation')
            if any(re.search(r'\s', str(path)) for path in (self.root, self.agent)):
                raise ValueError('Ghidra VM argument splitting requires coverage paths without whitespace')
        elif not command or Path(command[0]).name.lower() not in ('java', 'java.exe'):
            raise ValueError('coverage session requires a direct Java invocation')
        if any(arg.startswith('-javaagent:') for arg in command):
            raise ValueError('Java invocation already has an agent')
        if len(self.record['sessions']) >= MAX_SESSIONS:
            raise ValueError('coverage session limit exceeded')
        if digest(self.jar) != self.record['productionJarSha256']:
            raise ValueError('production classes changed during integration test')
        session_id = 'forge-integration-' + uuid.uuid4().hex
        execution = self.root / (session_id + '.exec')
        row = {'label': str(label), 'session': session_id, 'file': execution.name,
            'status': 'INCOMPLETE'}
        self.record['sessions'].append(row)
        self._save()
        option = (f'-javaagent:{self.agent}=destfile={execution},append=false,'
            f'includes=ghidradwarfforge.*,excludes={":".join(self.record["excludes"])},sessionid={session_id}')
        if headless:
            # Ghidra 12.0.3 analyzeHeadless is a thin wrapper around this exact
            # launch.sh invocation. Inject only into its analyzer JVM, never
            # into LaunchSupport or descendants through JAVA_TOOL_OPTIONS.
            vmargs = '-XX:ParallelGCThreads=2 -XX:CICompilerCount=2 -Djava.awt.headless=true ' + option
            measured = [str(launcher.parent / 'launch.sh'), 'fg', 'jdk', 'Ghidra-Headless',
                '2G', vmargs, 'ghidra.app.util.headless.AnalyzeHeadless', *command[1:]]
        else:
            measured = [command[0], option, *command[1:]]
        try:
            yield measured
            if not execution.is_file() or not 0 < execution.stat().st_size <= MAX_EXEC_BYTES:
                raise ValueError('missing or excessive integration execution data')
            if sum(p.stat().st_size for p in self.root.glob('*.exec')) > MAX_RUN_BYTES:
                raise ValueError('integration coverage run exceeds storage limit')
            if digest(self.jar) != self.record['productionJarSha256']:
                raise ValueError('production classes changed during integration test')
            row.update(status='ORACLE_PASSED', sha256=digest(execution))
        finally:
            self._save()

    def finish(self, evidence):
        """Bind the full existing harness outcome; a per-process success is insufficient."""
        if not self.enabled:
            return
        if self.closed:
            raise ValueError('coverage collection already finished')
        evidence = Path(evidence).resolve(strict=True)
        result = json.loads(evidence.read_text(encoding='utf-8'))
        if not passing_status(result.get('status')):
            raise ValueError('integration harness has no passing receipt')
        sessions = self.record['sessions']
        if not sessions or any(row['status'] != 'ORACLE_PASSED' for row in sessions):
            raise ValueError('integration coverage contains incomplete sessions')
        if digest(self.jar) != self.record['productionJarSha256']:
            raise ValueError('production classes changed during integration test')
        self.record.update(status='COLLECTED', evidenceSha256=digest(evidence))
        # Keep one concise evidence receipt beside the execution data; no fixtures.
        (self.root / 'oracle.json').write_bytes(evidence.read_bytes())
        self._save()
        validate_collection(self.root, self.jar)
        self.closed = True

    def record_forced_halt(self, label, exit_code):
        """Runtime.halt deliberately bypasses the agent's shutdown dump.

        These controls still run and their recovery assertions remain required;
        their execution is explicitly unmeasured, not silently missing data.
        """
        if not self.enabled:
            return
        if self.closed or exit_code != 73:
            raise ValueError('invalid forced-halt observation')
        self.record['unmeasuredForcedHalts'].append({'label': str(label), 'exitCode': exit_code,
            'reason': 'intentional Runtime.halt bypasses JaCoCo shutdown; behavioral control only'})
        self._save()


def validate_collection(root, jar):
    """Validate receipt integrity. Execution identities still require the Java verifier."""
    root = Path(root)
    record = json.loads((root / 'receipt.json').read_text(encoding='utf-8'))
    if record.get('schema') != 1 or record.get('status') != 'COLLECTED':
        raise ValueError('integration coverage collection is incomplete')
    if record.get('productionJarSha256') != digest(jar):
        raise ValueError('integration coverage uses different production classes')
    if record.get('evidenceSha256') != digest(root / 'oracle.json'):
        raise ValueError('integration oracle receipt changed')
    oracle = json.loads((root / 'oracle.json').read_text(encoding='utf-8'))
    if not passing_status(oracle.get('status')):
        raise ValueError('integration oracle did not pass')
    if (not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', record.get('suite', ''))
            or record.get('layer') not in ('native-java', 'headless', 'windows')
            or record.get('host') not in ('posix', 'nt')):
        raise ValueError('invalid integration collection metadata')
    with ZipFile(jar) as archive:
        classes = [name[:-6].replace('/', '.') for name in archive.namelist()
            if name.endswith('.class')]
    if record.get('productionClasses') != len(classes):
        raise ValueError('incorrect production class population')
    excludes = record.get('excludes', [])
    if (not isinstance(excludes, list)
            or any(not isinstance(pattern, str) or not re.fullmatch(
                r'ghidradwarfforge\.[A-Za-z0-9_.]+(?:\$\*)?', pattern) for pattern in excludes)
            or any(fnmatch.fnmatchcase(name, pattern) for name in classes for pattern in excludes)):
        raise ValueError('invalid or production-matching test exclusion')
    halts = record.get('unmeasuredForcedHalts', [])
    if (not isinstance(halts, list) or any(not isinstance(row, dict)
            or row.get('exitCode') != 73 or not isinstance(row.get('label'), str)
            or row.get('reason') != 'intentional Runtime.halt bypasses JaCoCo shutdown; behavioral control only'
            for row in halts)):
        raise ValueError('invalid unmeasured forced-halt record')
    sessions = record.get('sessions', [])
    if not 0 < len(sessions) <= MAX_SESSIONS:
        raise ValueError('invalid integration session count')
    names = set()
    size = 0
    for row in sessions:
        session = row.get('session', '')
        if not re.fullmatch(r'forge-integration-[0-9a-f]{32}', session):
            raise ValueError('invalid integration session identity')
        name = session + '.exec'
        if row.get('file') != name or name in names or row.get('status') != 'ORACLE_PASSED':
            raise ValueError('invalid or incomplete integration session')
        names.add(name)
        path = root / name
        if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= MAX_EXEC_BYTES:
            raise ValueError('invalid integration execution file')
        size += path.stat().st_size
        if digest(path) != row.get('sha256'):
            raise ValueError('integration execution data changed')
    if size > MAX_RUN_BYTES or names != {p.name for p in root.glob('*.exec')}:
        raise ValueError('excessive or unrecorded integration execution data')
    return record
