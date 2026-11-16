"""Receipt/admission controls only; real JaCoCo execution is checked separately."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from zipfile import ZipFile


SPEC = importlib.util.spec_from_file_location('integration_coverage',
    Path(__file__).resolve().parents[1] / 'integration/integration_coverage.py')
coverage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(coverage)


class IntegrationCoverageTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='integration-coverage-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.jar = self.root / 'production.jar'
        with ZipFile(self.jar, 'w') as archive:
            archive.writestr('ghidradwarfforge/Fixture.class', b'receipt fixture, not real bytecode')
        self.agent = self.root / 'agent.jar'
        self.agent.write_bytes(b'receipt fixture, not an agent')
        self.env = {'FORGE_INTEGRATION_COVERAGE_OUTPUT': str(self.root / 'output with spaces'),
            'FORGE_INTEGRATION_COVERAGE_AGENT': str(self.agent)}
        self.oracle = self.root / 'result.json'
        self.oracle.write_text(json.dumps({'status': 'PASS_TEST_ORACLE'}))

    def collection(self):
        return coverage.Collection('receipt-test', self.jar, 'native-java', environment=self.env)

    def execution(self, collection):
        row = collection.record['sessions'][-1]
        return collection.root / row['file']

    def collected(self):
        collection = self.collection()
        with collection.session(['java', '-cp', 'unchanged', 'Main'], 'first') as command:
            self.assertEqual(command[0], 'java')
            self.assertEqual(command[2:], ['-cp', 'unchanged', 'Main'])
            self.assertIn('append=false', command[1])
            self.execution(collection).write_bytes(b'not real execution: receipt checks only')
        collection.finish(self.oracle)
        return collection

    def test_disabled_is_noop(self):
        collection = coverage.Collection('unused', self.root / 'absent.jar', 'unused', environment={})
        command = ['not-java', 'untouched']
        with collection.session(command, 'no-op') as actual:
            self.assertIs(actual, command)
        collection.finish(self.root / 'absent.json')
        self.assertFalse((self.root / 'output with spaces').exists())
        with collection.launcher_java('unchanged-java', 'disabled') as selected:
            self.assertEqual(selected, 'unchanged-java')
        with collection.launcher_headless('unchanged-ghidra', 'disabled') as selected:
            self.assertEqual(selected, 'unchanged-ghidra')

    def headless_collection(self):
        ghidra = self.root / 'ghidra'
        installed = ghidra / 'Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar'
        installed.parent.mkdir(parents=True, exist_ok=True)
        installed.write_bytes(self.jar.read_bytes())
        support = ghidra / 'support'
        support.mkdir(exist_ok=True)
        (support / 'analyzeHeadless').touch()
        launcher = support / 'launch.sh'
        # This executable validates process plumbing only, never Java coverage.
        launcher.write_text('#!' + sys.executable + '\n'
            'import json,os,re,sys\n'
            'from pathlib import Path\n'
            'Path(re.search(r"destfile=([^,]+)", sys.argv[5])[1]).write_bytes(b"receipt fixture only")\n'
            'print(json.dumps({"pid":os.getpid(),"argv":sys.argv[1:]}))\n'
            'raise SystemExit(int(os.environ.get("FIXTURE_EXIT", "0")))\n')
        launcher.chmod(0o700)
        env = dict(self.env, FORGE_INTEGRATION_COVERAGE_OUTPUT=str(self.root / 'headless'))
        return ghidra, coverage.Collection('wrapper-test', installed, 'headless', environment=env)

    @unittest.skipUnless(os.name == 'posix', 'Linux headless wrapper adapter')
    def test_headless_wrapper_preserves_arguments_pid_and_exit(self):
        ghidra, collection = self.headless_collection()
        arguments = ['project with spaces', 'Formatters', '-readOnly', '-postScript',
            'GhidraDwarfForgeReadOnly.java', 'λ "quoted"', '', '$(never-execute)', 'line\nbreak']
        with collection.launcher_headless(ghidra, 'expected-failure') as selected:
            adapter = Path(selected) / 'support/analyzeHeadless'
            process = subprocess.Popen([adapter, *arguments], stdout=subprocess.PIPE, text=True,
                env=dict(os.environ, FIXTURE_EXIT='10'))
            output, _ = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 10)
            observed = json.loads(output)
            self.assertEqual(observed['pid'], process.pid)
            self.assertEqual(observed['argv'][6:], arguments)
            self.assertEqual(observed['argv'][:4], ['fg', 'jdk', 'Ghidra-Headless', '2G'])
        self.assertFalse(adapter.exists())
        collection.finish(self.oracle)
        record = coverage.validate_collection(collection.root, collection.jar)
        self.assertEqual(len(record['sessions']), 1)
        self.assertEqual(len(record['launcherInvocations']), 1)

    @unittest.skipUnless(os.name == 'posix', 'Linux headless wrapper adapter')
    def test_headless_wrapper_rejects_missing_duplicate_data_and_failed_oracle(self):
        for failure in ('missing', 'duplicate', 'no-data', 'oracle'):
            with self.subTest(failure=failure):
                ghidra, collection = self.headless_collection()
                with self.assertRaises((ValueError, AssertionError)):
                    with collection.launcher_headless(ghidra, failure) as selected:
                        adapter = Path(selected) / 'support/analyzeHeadless'
                        if failure != 'missing':
                            subprocess.run([adapter], check=True, stdout=subprocess.PIPE, timeout=10)
                        if failure == 'duplicate':
                            result = subprocess.run([adapter], capture_output=True, timeout=10)
                            self.assertNotEqual(result.returncode, 0)
                        elif failure == 'no-data':
                            self.execution(collection).unlink()
                        elif failure == 'oracle':
                            raise AssertionError('wrapper behavior failed')
                self.assertFalse(adapter.exists())
                with self.assertRaisesRegex(ValueError, 'incomplete'):
                    collection.finish(self.oracle)

    def launcher_record(self, wrapper, collection, session):
        request = Path(wrapper).parent / 'requests' / (session + '.json')
        request.write_text(json.dumps({'session': session}))
        (collection.root / (session + '.exec')).write_bytes(b'receipt fixture, not real execution')

    @unittest.skipUnless(os.name == 'posix', 'Linux launcher adapter')
    def test_launcher_keeps_preview_and_action_separate(self):
        java = self.root / 'java'
        java.write_text('receipt fixture, never executed')
        java.chmod(0o700)
        collection = self.collection()
        with collection.launcher_java(java, 'install') as wrapper:
            for digit in ('1', '2'):
                self.launcher_record(wrapper, collection, 'forge-integration-' + digit * 32)
        self.assertFalse(Path(wrapper).exists())
        collection.finish(self.oracle)
        record = coverage.validate_collection(collection.root, self.jar)
        self.assertEqual(len(record['sessions']), 2)
        self.assertEqual(len(record['launcherInvocations'][0]['sessions']), 2)
        with self.assertRaisesRegex(ValueError, 'already finished'):
            with collection.launcher_java(java, 'late'):
                self.fail('finished collector yielded')

    @unittest.skipUnless(os.name == 'posix', 'Linux launcher adapter')
    def test_failed_launcher_oracle_cannot_be_finished(self):
        java = self.root / 'java'
        java.touch()
        java.chmod(0o700)
        collection = self.collection()
        with self.assertRaisesRegex(AssertionError, 'behavior failed'):
            with collection.launcher_java(java, 'install') as wrapper:
                self.launcher_record(wrapper, collection, 'forge-integration-' + '1' * 32)
                raise AssertionError('behavior failed')
        with self.assertRaisesRegex(ValueError, 'incomplete sessions'):
            collection.finish(self.oracle)

    @unittest.skipUnless(os.name == 'posix', 'Linux launcher adapter')
    def test_missing_jvm_leaves_an_incomplete_invocation(self):
        java = self.root / 'java'
        java.touch()
        java.chmod(0o700)
        collection = self.collection()
        with collection.session(['java', 'Main'], 'earlier-passing-process'):
            self.execution(collection).write_bytes(b'receipt fixture')
        # Existing valid data cannot compensate for a launcher that never reaches Java.
        with self.assertRaisesRegex(ValueError, 'missing or excessive launcher'):
            with collection.launcher_java(java, 'never-started'):
                pass
        with self.assertRaisesRegex(ValueError, 'incomplete launcher'):
            collection.finish(self.oracle)

    @unittest.skipUnless(os.name == 'posix', 'Linux launcher adapter')
    def test_launcher_session_integrity(self):
        java = self.root / 'java'
        java.touch()
        java.chmod(0o700)
        for mutation in ('missing-exec', 'foreign-id', 'renamed-record', 'extra-fields', 'linked-exec'):
            with self.subTest(mutation=mutation):
                collection = self.collection()
                session = 'forge-integration-' + '1' * 32
                with self.assertRaises(ValueError):
                    with collection.launcher_java(java, mutation) as wrapper:
                        self.launcher_record(wrapper, collection, session)
                        request = Path(wrapper).parent / 'requests' / (session + '.json')
                        execution = collection.root / (session + '.exec')
                        if mutation == 'missing-exec':
                            execution.unlink()
                        elif mutation == 'foreign-id':
                            request.write_text('{"session":"foreign"}')
                        elif mutation == 'renamed-record':
                            request.rename(request.with_name('wrong.json'))
                        elif mutation == 'extra-fields':
                            request.write_text(json.dumps({'session': session, 'status': 'PASSED'}))
                        else:
                            execution.unlink()
                            execution.symlink_to(self.agent)

    def test_partial_configuration_rejected(self):
        for key in self.env:
            with self.assertRaisesRegex(ValueError, 'both output and agent'):
                coverage.Collection('test', self.jar, 'headless', environment={key: self.env[key]})

    def test_production_cannot_be_excluded(self):
        with ZipFile(self.jar, 'w') as archive:
            archive.writestr('ghidradwarfforge/ProbeProduction.class', b'fixture')
        with self.assertRaisesRegex(ValueError, 'remove a production class'):
            coverage.Collection('receipt-test', self.jar, 'native-java', environment=self.env,
                test_classes=('ghidradwarfforge.ProbeProduction',))

    def test_production_nested_probe_is_retained(self):
        with ZipFile(self.jar, 'w') as archive:
            archive.writestr('ghidradwarfforge/elf/GdbCompanion$Probe.class', b'fixture')
        collection = coverage.Collection('receipt-test', self.jar, 'native-java', environment=self.env,
            test_classes=('ghidradwarfforge.output.BuildIdInstallationProbe',))
        self.assertEqual(collection.record['productionClasses'], 1)
        self.assertEqual(collection.record['excludes'], ['ghidradwarfforge.output.BuildIdInstallationProbe',
            'ghidradwarfforge.output.BuildIdInstallationProbe$*'])

    def test_shell_and_existing_agent_rejected(self):
        collection = self.collection()
        for command in (['sh', '-c', 'java Main'], ['java', '-javaagent:other.jar', 'Main']):
            with self.assertRaises(ValueError), collection.session(command, 'invalid'):
                self.fail('invalid command yielded')

    def test_each_jvm_has_unique_output_and_session(self):
        collection = self.collection()
        commands = []
        for _ in range(2):
            with collection.session(['java.exe', 'Main'], 'repeated-label') as command:
                commands.append(command)
                self.execution(collection).write_bytes(b'fixture')
        self.assertNotEqual(commands[0][1], commands[1][1])
        collection.finish(self.oracle)
        self.assertEqual(len(coverage.validate_collection(collection.root, self.jar)['sessions']), 2)

    def test_failed_behavior_does_not_accept_execution(self):
        collection = self.collection()
        with self.assertRaisesRegex(AssertionError, 'oracle failed'):
            with collection.session(['java', 'Main'], 'failure'):
                self.execution(collection).write_bytes(b'fixture')
                raise AssertionError('oracle failed')
        with self.assertRaisesRegex(ValueError, 'incomplete sessions'):
            collection.finish(self.oracle)
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            coverage.validate_collection(collection.root, self.jar)

    def test_missing_execution_rejected(self):
        collection = self.collection()
        with self.assertRaisesRegex(ValueError, 'missing or excessive'):
            with collection.session(['java', 'Main'], 'no-data'):
                pass

    def test_production_change_rejected(self):
        collection = self.collection()
        with self.assertRaisesRegex(ValueError, 'production classes changed'):
            with collection.session(['java', 'Main'], 'change'):
                self.execution(collection).write_bytes(b'fixture')
                self.jar.write_bytes(b'replaced production')

    def test_entire_harness_must_pass(self):
        collection = self.collection()
        with collection.session(['java', 'Main'], 'one-process'):
            self.execution(collection).write_bytes(b'fixture')
        self.oracle.write_text('{"status": "FAIL"}')
        with self.assertRaisesRegex(ValueError, 'no passing receipt'):
            collection.finish(self.oracle)

    def test_tampered_or_unrecorded_execution_rejected(self):
        for mutation in ('bytes', 'extra', 'missing', 'duplicate', 'traversal'):
            with self.subTest(mutation=mutation):
                collection = self.collected()
                path = self.execution(collection)
                if mutation == 'bytes':
                    path.write_bytes(b'changed')
                elif mutation == 'extra':
                    (collection.root / 'unknown.exec').write_bytes(b'extra')
                elif mutation == 'missing':
                    path.unlink()
                elif mutation == 'duplicate':
                    collection.record['sessions'].append(collection.record['sessions'][0].copy())
                    collection._save()
                else:
                    collection.record['sessions'][0]['file'] = '../outside.exec'
                    collection._save()
                with self.assertRaises(ValueError):
                    coverage.validate_collection(collection.root, self.jar)

    def test_wrong_jar_and_changed_oracle_rejected(self):
        collection = self.collected()
        other = self.root / 'other.jar'
        other.write_bytes(b'wrong jar')
        with self.assertRaisesRegex(ValueError, 'different production classes'):
            coverage.validate_collection(collection.root, other)
        (collection.root / 'oracle.json').write_text('{"status":"FAIL"}')
        with self.assertRaisesRegex(ValueError, 'oracle receipt changed'):
            coverage.validate_collection(collection.root, self.jar)

    def test_closed_collection_cannot_append(self):
        collection = self.collected()
        with self.assertRaisesRegex(ValueError, 'already finished'), collection.session(['java', 'Main'], 'late'):
            self.fail('closed session yielded')

    def test_misleading_pass_status_rejected(self):
        for status in ('PASS_WITH_FAILURES?', 'PASSED', 'PASS-but-skipped', 'PASS ', None):
            collection = self.collection()
            with collection.session(['java', 'Main'], 'valid-process'):
                self.execution(collection).write_bytes(b'fixture')
            self.oracle.write_text(json.dumps({'status': status}))
            with self.assertRaisesRegex(ValueError, 'no passing receipt'):
                collection.finish(self.oracle)

    def test_forced_halts_explicitly_unmeasured(self):
        collection = self.collection()
        with self.assertRaisesRegex(ValueError, 'invalid forced-halt'):
            collection.record_forced_halt('wrong-exit', 1)
        collection.record_forced_halt('interrupted-publish', 73)
        collection.record_forced_halt('attachment-recovery-child', 89)
        with self.assertRaisesRegex(ValueError, 'incomplete sessions'):
            collection.finish(self.oracle)
        with collection.session(['java', 'Main'], 'recovery'):
            self.execution(collection).write_bytes(b'fixture')
        collection.finish(self.oracle)
        record = coverage.validate_collection(collection.root, self.jar)
        self.assertEqual(len(record['sessions']), 1)
        self.assertEqual(record['unmeasuredForcedHalts'][0]['exitCode'], 73)
        self.assertEqual(record['unmeasuredForcedHalts'][1]['exitCode'], 89)
        with self.assertRaisesRegex(ValueError, 'invalid forced-halt'):
            collection.record_forced_halt('late', 73)

    def test_metadata_cannot_drop_population_or_hide_crashes(self):
        for field, value in (('productionClasses', 0), ('excludes', ['ghidradwarfforge.*']),
                ('excludes', ['ghidradwarfforge.Fixture']), ('layer', 'unknown'),
                ('unmeasuredForcedHalts', [{'label': 'crash', 'exitCode': 1}])):
            collection = self.collected()
            collection.record[field] = value
            collection._save()
            with self.assertRaises(ValueError):
                coverage.validate_collection(collection.root, self.jar)

    def test_pinned_headless_adapter_preserves_arguments(self):
        install = self.root / 'ghidra'
        support = install / 'support'
        support.mkdir(parents=True)
        launcher = support / 'analyzeHeadless'
        launcher.write_text('fixture')
        installed = install / 'Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar'
        installed.parent.mkdir(parents=True)
        installed.write_bytes(self.jar.read_bytes())
        environment = dict(self.env, FORGE_INTEGRATION_COVERAGE_OUTPUT=str(self.root / 'headless'))
        collection = coverage.Collection('headless-test', installed, 'headless', environment=environment)
        arguments = ['project directory', 'project', '-readOnly', '-postScript', 'Check.java']
        with collection.session([launcher, *arguments], 'readback', headless=True) as command:
            self.assertEqual(command[:5], [str(support / 'launch.sh'), 'fg', 'jdk', 'Ghidra-Headless', '2G'])
            self.assertIn('-javaagent:', command[5])
            self.assertEqual(command[6:], ['ghidra.app.util.headless.AnalyzeHeadless', *arguments])
            self.execution(collection).write_bytes(b'fixture')
        collection.finish(self.oracle)
        foreign = coverage.Collection('wrong-install', self.jar, 'headless', environment=environment)
        with self.assertRaisesRegex(ValueError, 'measured installation'):
            with foreign.session([launcher, *arguments], 'wrong', headless=True):
                self.fail('foreign installation accepted')
        spaces = coverage.Collection('spaces', installed, 'headless', environment=self.env)
        with self.assertRaisesRegex(ValueError, 'without whitespace'):
            with spaces.session([launcher, *arguments], 'spaces', headless=True):
                self.fail('unsafe headless option splitting accepted')


if __name__ == '__main__':
    unittest.main()
