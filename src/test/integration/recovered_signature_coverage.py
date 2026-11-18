"""Coverage receipts for the complete recovered-return and parameter workflows."""
from contextlib import nullcontext
import hashlib
import json
from pathlib import Path

from integration_coverage import Collection, digest


class Measurement:
    def __init__(self, kind, module):
        self.kind = kind
        self.collection = Collection('recovered-' + kind, module / 'lib/GhidraDwarfForge.jar', 'headless')

    def session(self, command, label):
        # Historical comparison packages retain their behavioral role but must
        # never contribute incompatible production probes to this collection.
        if Path(command[0]).name != 'analyzeHeadless' or label == 'previous':
            return nullcontext(command)
        return self.collection.session(command, label, headless=True)

    def finish(self, case, repository, module, before, after, project_before, project_after, metadata, dies, facts):
        assert before == after
        result = json.loads((case / 'result.json').read_text())
        assert result['status'] == 'PASS'
        models = [json.loads((case / (phase + '.json')).read_text()) for phase in ('import', 'fixed', 'repeat')]
        model_hashes = [hashlib.sha256(json.dumps(row['functions'], sort_keys=True).encode()).hexdigest() for row in models]
        assert len(set(model_hashes)) == 1
        reports = []
        for phase in ('fixed', 'repeat'):
            report, = [json.JSONDecoder().raw_decode(line.split('GhidraDwarfForge report: ', 1)[1])[0]
                for line in (case / (phase + '.log')).read_text().splitlines() if 'GhidraDwarfForge report: {' in line]
            assert not report['failedFunctions'] and report['failure'] is None and report['counts']['functionsFailed'] == 0
            assert report['artifacts']['inputSha256'] == result['inputSha256']
            assert [report['artifacts']['outputSha256'], report['artifacts']['sourceSha256']] == result['artifactSha256']
            reports.append({'phase': phase, 'counts': report['counts'], 'artifacts': report['artifacts'],
                'diagnostics': report['diagnostics'], 'omittedLocations': report['omittedLocations']})
        strict = json.loads((case / 'strict-checks.log.check.json').read_text())
        assert strict['status'] == 'PASS' and strict['uncorroborated_errors'] == 0
        required = {row['name'] for row in metadata['functions']}
        functions = []
        for die in dies:
            name = facts.facts.die_name(die)
            if die['tag'] != 'DW_TAG_subprogram' or name not in required:
                continue
            children = [row for row in facts.children(dies, dies.index(die)) if row['tag'] == 'DW_TAG_formal_parameter']
            functions.append({'name': name, 'attributes': sorted(die['attrs']),
                'parameters': [{'name': facts.facts.die_name(row), 'attributes': sorted(row['attrs'])} for row in children]})
        harness = {str(Path(name).relative_to(repository)): value for name, value in before.items()
            if Path(name).is_relative_to(repository) and Path(name).relative_to(repository).parts[0] in ('src', 'ghidra_scripts')}
        assert digest(module / 'ghidra_scripts/GhidraDwarfForge.java') == digest(repository / 'ghidra_scripts/GhidraDwarfForge.java')
        evidence = {**result, 'status': 'PASS_RECOVERED_SIGNATURE_MEASUREMENT', 'kind': self.kind,
            'target': 'x86_64', 'role': 'exec', 'validators': ['readelf', 'llvm-dwarfdump', 'libdwarf-consumer'],
            'harnessSha256': harness, 'protectedBefore': before, 'protectedAfter': after,
            'projectBefore': project_before, 'projectAfter': project_after,
            'modelHashes': model_hashes, 'functions': metadata['functions'], 'functionDIEs': functions,
            'reports': reports, 'strict': strict,
            'gdb': [json.loads((case / (variant + '-gdb.json')).read_text()) for variant in ('compiler', 'forge')],
            'historicalComparisonMeasured': False}
        path = case / 'coverage-oracle.json'
        path.write_text(json.dumps(evidence, indent=4) + '\n')
        self.collection.finish(path)
