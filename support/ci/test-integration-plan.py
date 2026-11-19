#!/usr/bin/env python3
"""Controls for inventory preservation and fail-closed grouped-job admission."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('integration_plan', HERE / 'integration-plan.py')
plan = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(plan)
INVENTORY = json.loads((HERE / 'integration-groups.json').read_text())
COMMIT = '1' * 40
RUN = 12345
ATTEMPT = 2


def successful_jobs():
    """API-shaped synthetic observations; never evidence of real CI execution."""
    jobs = []
    for number, group in enumerate(plan.matrix(INVENTORY)['include'], 1):
        selected = set(json.loads(group['steps']))
        jobs.append({'id': number, 'name': 'target-integration ({target}, {group})'.format(**group),
            'head_sha': COMMIT, 'run_id': RUN, 'run_attempt': ATTEMPT,
            'status': 'completed', 'conclusion': 'success',
            'steps': [{'name': '[' + row['id'] + '] ' + row['name'],
                'status': 'completed',
                'conclusion': 'success' if row['id'] in selected else 'skipped'}
                for row in INVENTORY['steps']]})
    return jobs


def admit(jobs):
    return plan.verify_jobs(INVENTORY, jobs, commit=COMMIT, run=RUN, attempt=ATTEMPT)


class InventoryTests(unittest.TestCase):
    def test_preserves_each_architecture_once(self):
        expected = {'x86_64': (149, 8), 'aarch64': (98, 6), 'arm32': (51, 4),
            'mips32be': (55, 3), 'mips32le': (55, 3)}
        matrix = plan.matrix(INVENTORY)['include']
        self.assertEqual(24, len(matrix))
        for target, (count, groups) in expected.items():
            rows = [row for row in matrix if row['target'] == target]
            tests = [test for row in rows for test in row['tests']]
            self.assertEqual(groups, len(rows))
            self.assertEqual(count, len(tests))
            self.assertEqual(count, len(set(tests)))

    def test_keeps_nested_and_performance_commands_whole(self):
        rows = {row['baselineStep']: row for row in INVENTORY['steps']}
        self.assertEqual({'x86_64': 'performance'}, rows[122]['groups'])
        self.assertEqual('Static objects preserve lexical shadowing and failure isolation', rows[125]['name'])
        self.assertEqual('source', rows[125]['groups']['x86_64'])
        self.assertEqual('source', rows[125]['groups']['aarch64'])
        self.assertEqual('primary', rows[176]['groups']['x86_64'])
        self.assertEqual('modes', rows[152]['groups']['arm32'])
        self.assertEqual('aggregate', rows[174]['groups']['arm32'])

    def test_rejects_missing_target_assignment(self):
        broken = copy.deepcopy(INVENTORY)
        del broken['steps'][71]['groups']['mips32be']
        with self.assertRaisesRegex(ValueError, 'assignment'):
            plan.matrix(broken)

    def test_rejects_architecture_removal_or_duplication(self):
        for targets in [list(plan.TARGETS[:-1]), list(plan.TARGETS) + ['x86_64']]:
            broken = copy.deepcopy(INVENTORY)
            broken['targets'] = targets
            with self.assertRaisesRegex(ValueError, 'architecture set'):
                plan.matrix(broken)

    def test_rejects_unknown_and_repeated_step_targets(self):
        for targets in [['riscv64'], ['x86_64', 'x86_64']]:
            broken = copy.deepcopy(INVENTORY)
            broken['steps'][0]['targets'] = targets
            with self.assertRaisesRegex(ValueError, 'step inventory'):
                plan.matrix(broken)

    def test_rejects_splitting_each_known_dependency(self):
        for dependency in INVENTORY['dependencies']:
            broken = copy.deepcopy(INVENTORY)
            row = next(row for row in broken['steps'] if row['id'] == dependency['steps'][-1])
            target = next(iter(row['groups']))
            row['groups'][target] = 'orphan'
            with self.subTest(dependency=dependency['reason']):
                with self.assertRaisesRegex(ValueError, 'dependent tests split'):
                    plan.matrix(broken)

    def test_rejects_reordering_and_dropped_steps(self):
        for operation in ('reverse', 'delete', 'duplicate'):
            broken = copy.deepcopy(INVENTORY)
            if operation == 'reverse':
                broken['steps'].reverse()
            elif operation == 'delete':
                del broken['steps'][71]
            else:
                broken['steps'].insert(72, broken['steps'][71])
            with self.assertRaisesRegex(ValueError, 'step inventory'):
                plan.matrix(broken)

    def test_baseline_commands_conditions_and_actions_are_bound(self):
        import yaml
        workflow = yaml.safe_load((HERE.parent.parent / '.github/workflows/ci.yml').read_text())
        plan.validate_workflow(INVENTORY, workflow)
        for number, field, value in [(71, 'run', 'true'), (123, 'if', "matrix.target == 'x86_64'"),
                (0, 'uses', 'actions/checkout@v1')]:
            broken = copy.deepcopy(workflow)
            row = next(step for step in broken['jobs']['target-integration']['steps']
                if step.get('name', '').startswith(f'[target-{number + 1:03}]'))
            row[field] = value
            with self.subTest(number=number, field=field):
                with self.assertRaisesRegex(ValueError, 'baseline command, condition or action changed|group assignment predicate'):
                    plan.validate_workflow(INVENTORY, broken)

    def test_condition_parser_rejects_unreviewed_or_executable_expressions(self):
        for expression in ["__import__('os').system('false')", 'matrix.unreviewed == 1',
                'True if True else False', '1', "'nonboolean'", 'cancelled()']:
            with self.subTest(expression=expression):
                with self.assertRaises(ValueError):
                    plan.successful_condition(expression, 'arm32')
        self.assertTrue(plan.successful_condition(
            "always() && (matrix.target == 'arm32' || matrix.target == 'x86_64')", 'arm32'))
        self.assertFalse(plan.successful_condition("matrix.target != 'arm32'", 'arm32'))

    def test_each_group_has_standalone_harness_prerequisites(self):
        import yaml
        workflow = yaml.safe_load((HERE.parent.parent / '.github/workflows/ci.yml').read_text())
        for missing in (' testClasses', ' jar'):
            broken = copy.deepcopy(workflow)
            setup = next(step for step in broken['jobs']['target-integration']['steps']
                if step.get('name', '').startswith('[target-023]'))
            setup['run'] = setup['run'].replace(missing, '')
            with self.subTest(missing=missing):
                with self.assertRaisesRegex(ValueError, 'harness classes and production JAR'):
                    plan.validate_workflow(INVENTORY, broken)
        for group in plan.matrix(INVENTORY)['include']:
            self.assertIn('target-023', json.loads(group['steps']))


class AdmissionTests(unittest.TestCase):
    def test_complete_success(self):
        result = admit(successful_jobs())
        self.assertEqual('PASS', result['status'])
        self.assertEqual(24, len(result['jobs']))

    def test_missing_or_duplicated_group(self):
        jobs = successful_jobs()
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            admit(jobs[:-1])
        with self.assertRaisesRegex(ValueError, 'repeated'):
            admit(jobs + [jobs[0]])

    def test_missing_failed_cancelled_skipped_and_running_groups(self):
        for outcome in ['failure', 'cancelled', 'skipped', 'timed_out', 'neutral', None]:
            jobs = successful_jobs()
            jobs[0]['conclusion'] = outcome
            with self.subTest(outcome=outcome):
                with self.assertRaisesRegex(ValueError, 'failed or unfinished'):
                    admit(jobs)
        jobs = successful_jobs()
        jobs[0]['status'] = 'in_progress'
        with self.assertRaisesRegex(ValueError, 'unfinished'):
            admit(jobs)

    def test_stale_commit_run_and_attempt(self):
        for field, value in [('head_sha', '2' * 40), ('run_id', RUN - 1), ('run_attempt', 1)]:
            jobs = successful_jobs()
            jobs[0][field] = value
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, 'stale'):
                    admit(jobs)

    def test_pr_merge_commit_remains_distinct_from_api_head(self):
        result = plan.verify_jobs(INVENTORY, successful_jobs(), commit='2' * 40,
            head_commit=COMMIT, run=RUN, attempt=ATTEMPT)
        self.assertEqual('2' * 40, result['commit'])
        self.assertEqual(COMMIT, result['headCommit'])
        with self.assertRaisesRegex(ValueError, 'stale'):
            plan.verify_jobs(INVENTORY, successful_jobs(), commit='2' * 40,
                head_commit='3' * 40, run=RUN, attempt=ATTEMPT)

    def test_unknown_group(self):
        jobs = successful_jobs()
        jobs[0]['name'] = 'target-integration (x86_64, unknown)'
        with self.assertRaisesRegex(ValueError, 'unexpected'):
            admit(jobs)

    def test_reused_job_id_or_changed_step_name(self):
        jobs = successful_jobs()
        jobs[1]['id'] = jobs[0]['id']
        with self.assertRaisesRegex(ValueError, 'repeated'):
            admit(jobs)
        jobs = successful_jobs()
        jobs[0]['steps'][0]['name'] = '[target-001] Different action'
        with self.assertRaisesRegex(ValueError, 'name differs'):
            admit(jobs)
        jobs = successful_jobs()
        jobs[0]['steps'][0]['status'] = 'in_progress'
        with self.assertRaisesRegex(ValueError, 'not complete'):
            admit(jobs)

    def test_green_job_cannot_hide_missing_or_skipped_tests(self):
        for outcome in ['skipped', 'failure', 'cancelled', None, 'absent']:
            jobs = successful_jobs()
            primary = next(job for job in jobs if job['name'] == 'target-integration (x86_64, primary)')
            step = next(step for step in primary['steps'] if step['name'].startswith('[target-072]'))
            if outcome == 'absent':
                primary['steps'].remove(step)
            else:
                step['conclusion'] = outcome
            with self.subTest(outcome=outcome):
                with self.assertRaisesRegex(ValueError, 'step missing, skipped or failed'):
                    admit(jobs)

    def test_unassigned_tests_do_not_run_twice(self):
        jobs = successful_jobs()
        job = next(job for job in jobs if job['name'] == 'target-integration (arm32, primary)')
        step = next(step for step in job['steps'] if step['name'].startswith('[target-174]'))
        step['conclusion'] = 'success'
        with self.assertRaisesRegex(ValueError, 'unassigned'):
            admit(jobs)

    def test_repeated_step_and_reordered_dependencies(self):
        jobs = successful_jobs()
        jobs[0]['steps'].append(jobs[0]['steps'][0])
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            admit(jobs)
        jobs = successful_jobs()
        jobs[0]['steps'].reverse()
        with self.assertRaisesRegex(ValueError, 'order changed'):
            admit(jobs)


if __name__ == '__main__':
    unittest.main()
