#!/usr/bin/env python3
"""Validate the architecture inventory and produce a complete integration matrix.

The inventory records the unchanged sequential workflow before grouping. It is
not evidence that grouped jobs have run; admission of those jobs is separate.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re


TARGETS = ('x86_64', 'aarch64', 'arm32', 'mips32be', 'mips32le')
KINDS = {'setup', 'test', 'coverage', 'finalize'}
IDENTIFIER = re.compile(r'[a-z][a-z0-9-]{0,63}')


def successful_condition(expression, target):
    """Evaluate only the baseline's explicit target predicates, without eval."""
    if not expression:
        return True
    expression = (expression.replace('matrix.target', 'target')
        .replace('steps.formatter-tests.outcome', 'formatter')
        .replace('always()', 'True').replace('&&', ' and ').replace('||', ' or '))

    def value(node):
        if isinstance(node, ast.Constant) and type(node.value) in (str, bool):
            return node.value
        if isinstance(node, ast.Name) and node.id in ('target', 'formatter'):
            return target if node.id == 'target' else 'success'
        if isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)):
            values = [value(child) for child in node.values]
            if any(type(item) is not bool for item in values):
                raise ValueError('non-boolean condition operand')
            return all(values) if isinstance(node.op, ast.And) else any(values)
        if (isinstance(node, ast.Compare) and len(node.ops) == 1
                and isinstance(node.ops[0], (ast.Eq, ast.NotEq))):
            equal = value(node.left) == value(node.comparators[0])
            return equal if isinstance(node.ops[0], ast.Eq) else not equal
        raise ValueError('unsupported workflow condition: ' + expression)

    result = value(ast.parse(expression, mode='eval').body)
    if type(result) is not bool:
        raise ValueError('workflow condition is not boolean')
    return result


def step_digest(step):
    return hashlib.sha256(json.dumps(step, sort_keys=True,
        separators=(',', ':')).encode()).hexdigest()


def validate(inventory):
    if (inventory.get('schema') != 1 or inventory.get('targets') != list(TARGETS)
            or not re.fullmatch(r'[0-9a-f]{40}', inventory.get('baselineCommit', ''))
            or type(inventory.get('baselineRun')) is not int
            or inventory['baselineRun'] <= 0):
        raise ValueError('invalid inventory identity or architecture set')
    rows = inventory.get('steps')
    if not isinstance(rows, list) or not 1 <= len(rows) <= 500:
        raise ValueError('invalid step inventory')
    known = {}
    for number, row in enumerate(rows, 1):
        if (not isinstance(row, dict) or row.get('baselineStep') != number
                or row.get('id') != f'target-{number:03}'
                or not isinstance(row.get('name'), str) or not row['name']
                or row.get('kind') not in KINDS
                or not isinstance(row.get('targets'), list) or not row['targets']
                or row['targets'] != [t for t in TARGETS if t in row['targets']]
                or not isinstance(row.get('groups'), dict)
                or not re.fullmatch(r'[0-9a-f]{64}', row.get('stepSha256', ''))):
            raise ValueError('invalid or reordered step inventory at ' + str(number))
        if row['kind'] == 'test':
            if set(row['groups']) != set(row['targets']):
                raise ValueError('missing or extra architecture assignment: ' + row['id'])
            if any(not isinstance(group, str) or not IDENTIFIER.fullmatch(group)
                    for group in row['groups'].values()):
                raise ValueError('invalid group name: ' + row['id'])
        elif row['groups']:
            raise ValueError('setup/reporting cannot own test assignments')
        known[row['id']] = row
    dependencies = inventory.get('dependencies')
    if not isinstance(dependencies, list) or not dependencies:
        raise ValueError('missing dependency inventory')
    for dependency in dependencies:
        ids = dependency.get('steps', [])
        if (len(ids) < 2 or len(set(ids)) != len(ids)
                or any(identifier not in known for identifier in ids)
                or not dependency.get('reason')):
            raise ValueError('invalid dependency component')
        for target in TARGETS:
            owners = {known[identifier]['groups'][target] for identifier in ids
                if target in known[identifier]['groups']}
            if len(owners) > 1:
                raise ValueError('dependent tests split across groups: ' + target + ' ' + str(ids))
    return known


def validate_baseline(inventory, workflow):
    known = validate(inventory)
    job = workflow['jobs'][inventory['baselineJob']]
    if job['strategy']['matrix'] != {'target': list(TARGETS)}:
        raise ValueError('baseline architecture matrix changed')
    steps = job['steps']
    if len(steps) != len(known):
        raise ValueError('baseline step added or removed without inventory review')
    for row, step in zip(inventory['steps'], steps):
        targets = [target for target in TARGETS
            if successful_condition(step.get('if'), target)]
        if targets != row['targets'] or step_digest(step) != row['stepSha256']:
            raise ValueError('baseline command, condition or action changed: ' + row['id'])


def original_step(row, step):
    """Undo only reviewed scheduling changes before checking baseline hashes."""
    result = dict(step)
    if result.pop('name', None) != '[' + row['id'] + '] ' + row['name']:
        raise ValueError('grouped step name differs from inventory')
    if row['name'] != result.get('uses'):
        result['name'] = row['name']
    if result.get('uses', '').startswith('actions/upload-artifact@'):
        result['with'] = dict(result['with'])
        if result['with'].pop('overwrite', None) is not True:
            raise ValueError('rerun artifacts require explicit replacement')
    if row['kind'] != 'coverage':
        predicate = "contains(fromJSON(matrix.steps), '" + row['id'] + "')"
        actual = result.pop('if', '')
        if actual != predicate:
            prefix = predicate + ' && ('
            if not actual.startswith(prefix) or not actual.endswith(')'):
                raise ValueError('missing or changed group assignment predicate')
            result['if'] = actual[len(prefix):-1]
        if result.get('uses', '').startswith('actions/upload-artifact@'):
            name = result['with']['name']
            suffix = '-${{ matrix.group }}'
            if not name.endswith(suffix):
                raise ValueError('group artifact names must be unique')
            result['with']['name'] = name[:-len(suffix)]
        if row['id'] == 'target-023':
            prerequisites = 'prepareIntegrationCoverage testClasses jar'
            if result['run'].count(prerequisites) != 1:
                raise ValueError('group setup must prepare coverage tools, harness classes and production JAR')
            result['run'] = result['run'].replace(prerequisites, 'prepareIntegrationCoverage')
    else:
        if 'run' in result:
            result['run'] = result['run'].replace('$PWD/build/coverage-tools-input/production.jar',
                '$GHIDRA_INSTALL_DIR/Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar')
    return result


def validate_workflow(inventory, workflow):
    if inventory['baselineJob'] in workflow['jobs']:
        return validate_baseline(inventory, workflow)
    known = validate(inventory)
    seen = set()
    for job_name, kind in [('target-integration', 'tests'), ('target-coverage', 'coverage')]:
        job = workflow['jobs'][job_name]
        for step in job['steps']:
            match = re.match(r'^\[(target-[0-9]{3})\] ', step.get('name', ''))
            if not match:
                continue
            identifier = match.group(1)
            if identifier not in known or identifier in seen:
                raise ValueError('missing or duplicate baseline step ownership')
            row = known[identifier]
            if (row['kind'] == 'coverage') != (kind == 'coverage'):
                raise ValueError('whole-target report placed in a partial group')
            seen.add(identifier)
            restored = original_step(row, step)
            targets = [target for target in TARGETS if successful_condition(restored.get('if'), target)]
            if step_digest(restored) != row['stepSha256'] or targets != row['targets']:
                raise ValueError('baseline command, condition or action changed: ' + identifier)
    if seen != set(known):
        raise ValueError('baseline integration steps missing from grouped workflow')
    jobs = workflow['jobs']
    if (jobs['target-integration']['strategy']['matrix'] != '${{ fromJSON(needs.integration-plan.outputs.matrix) }}'
            or jobs['target-coverage']['strategy']['matrix'] != {'target': list(TARGETS)}):
        raise ValueError('grouped matrix no longer uses the checked inventory')
    requirements = {
        'target-integration': {'integration-plan', 'release-package', 'native-linux'},
        'target-coverage': {'target-integration'},
        'target-group-validation': {'target-integration'},
        'combined-java-coverage': {'target-coverage', 'target-group-validation'},
        'required-validation': {'target-integration', 'target-coverage', 'target-group-validation'},
    }
    for name, required in requirements.items():
        if not required <= set(jobs[name]['needs']):
            raise ValueError('grouped validation dependency missing: ' + name)


def matrix(inventory):
    validate(inventory)
    include = []
    for target in TARGETS:
        groups = sorted({row['groups'][target] for row in inventory['steps']
            if target in row['groups']})
        if not groups:
            raise ValueError('architecture has no tests: ' + target)
        for group in groups:
            tests = [row['id'] for row in inventory['steps']
                if row['groups'].get(target) == group]
            steps = [row['id'] for row in inventory['steps'] if target in row['targets']
                and (row['kind'] in ('setup', 'finalize') or row['id'] in tests)]
            include.append({'target': target, 'group': group,
                'steps': json.dumps(steps, separators=(',', ':')), 'tests': tests})
    return {'include': include}


def verify_jobs(inventory, jobs, *, commit, run, attempt, head_commit=None):
    """Reject absent, repeated, stale, skipped or failed required grouped jobs.

    Names must include inventory IDs so API observations cannot confuse repeated
    action names. This checks execution, not the separate coverage/oracle data.
    """
    expected = {(row['target'], row['group']): row for row in matrix(inventory)['include']}
    names = {f'target-integration ({target}, {group})': (target, group)
        for target, group in expected}
    known = {row['id']: row for row in inventory['steps']}
    # Pull requests execute a merge commit while the jobs API identifies the
    # PR head. Keep both identities explicit instead of treating them as equal.
    api_head = commit if head_commit is None else head_commit
    observed = {}
    for job in jobs:
        name = job.get('name', '')
        if not name.startswith('target-integration ('):
            continue
        if name not in names or name in observed or job.get('id') in observed.values():
            raise ValueError('unexpected or repeated integration group: ' + name)
        if (job.get('head_sha') != api_head or job.get('run_id') != run
                or job.get('run_attempt') != attempt or job.get('status') != 'completed'
                or job.get('conclusion') != 'success'):
            raise ValueError('stale, failed or unfinished integration group: ' + name)
        selected = expected[names[name]]
        required = set(json.loads(selected['steps']))
        outcomes = {}
        order = []
        for step in job.get('steps', []):
            match = re.match(r'^\[(target-[0-9]{3})\] ', step.get('name', ''))
            if match:
                identifier = match.group(1)
                if identifier in outcomes or identifier not in known:
                    raise ValueError('duplicate or unknown step identity: ' + name)
                if step['name'] != '[' + identifier + '] ' + known[identifier]['name']:
                    raise ValueError('integration step name differs from inventory: ' + name)
                if step.get('status') != 'completed':
                    raise ValueError('integration step is not complete: ' + name)
                outcomes[identifier] = step.get('conclusion')
                order.append(identifier)
        if order != sorted(order):
            raise ValueError('integration dependency order changed: ' + name)
        if any(outcomes.get(identifier) != 'success' for identifier in required):
            raise ValueError('required integration step missing, skipped or failed: ' + name)
        if any(outcome != 'skipped' for identifier, outcome in outcomes.items()
                if identifier not in required):
            raise ValueError('unassigned integration step executed: ' + name)
        observed[name] = job['id']
    if set(observed) != set(names):
        raise ValueError('incomplete integration group set')
    return {'status': 'PASS', 'commit': commit, 'headCommit': api_head, 'run': run, 'attempt': attempt,
        'jobs': observed, 'scope': 'Complete required group/step execution; coverage admission is separate'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=Path,
        default=Path('support/ci/integration-groups.json'))
    parser.add_argument('--baseline-workflow', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--github-output', action='store_true')
    args = parser.parse_args()
    inventory = json.loads(args.inventory.read_text())
    if args.baseline_workflow:
        import yaml
        validate_workflow(inventory, yaml.safe_load(args.baseline_workflow.read_text()))
    generated = matrix(inventory)
    result = json.dumps(generated, indent=4) + '\n'
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(result)
    else:
        print(result, end='')
    if args.github_output:
        with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
            output.write('matrix=' + json.dumps(generated, separators=(',', ':')) + '\n')


if __name__ == '__main__':
    main()
