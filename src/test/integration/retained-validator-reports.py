#!/usr/bin/env python3
"""Require passing checker receipts to retain their complete raw reports.

Run after the integration harnesses finish: a wrapper can overwrite the raw
report after the checker has already returned success. This checks retention,
not ELF identity or runtime behavior, which remain the individual tests' job.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path


def verify(root, exclude_validator_self_tests=False):
    helper = Path(__file__).with_name('check-dwarfdump.py')
    spec = importlib.util.spec_from_file_location('checker', helper)
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    reports = []
    failed_receipts = 0
    self_test_receipts = []
    for receipt in sorted(root.rglob('*.check.json')):
        relative = receipt.relative_to(root)
        if exclude_validator_self_tests and relative.parts[0] in (
                'check-dwarfdump', 'validation-evidence-controls'):
            # These exact top-level directories belong to validator self-tests.
            # Alias controls preserve non-JSON inputs at receipt paths; evidence
            # controls deliberately corrupt copies of completed raw reports.
            # Neither is production export evidence.
            self_test_receipts.append(str(relative))
            continue
        raw = receipt.with_name(receipt.name.removesuffix('.check.json'))
        stderr = raw.with_name(raw.name + '.stderr')
        try:
            metadata = json.loads(receipt.read_text())
            if metadata['status'] == 'FAILED':
                # Deliberately invalid artifacts have their own negative oracles.
                # They are not counted as passing retained reports.
                failed_receipts += 1
                continue
            checker.require(metadata['status'] == 'PASS', 'unknown checker status')
            checker.require(metadata['exit_status'] == 0, 'checker exited nonzero')
            checker.require(not stderr.read_bytes(), 'checker stderr is not empty')
            inherited = metadata.get('inherited_frame_evidence', {}).get('diagnostics', [])
            checked = checker.validate_output(raw.read_text(), inherited)
            checker.require(all(metadata[key] == value for key, value in checked.items()),
                'raw report differs from checker receipt')
        except (OSError, ValueError, KeyError, checker.ValidationFailure) as error:
            raise ValueError(str(receipt) + ': ' + str(error)) from error
        reports.append({'receipt': str(receipt.relative_to(root)),
            'receiptSha256': hashlib.sha256(receipt.read_bytes()).hexdigest(),
            'rawSha256': hashlib.sha256(raw.read_bytes()).hexdigest()})
    checker.require(bool(reports), 'no passing checker reports found')
    return {'status': 'PASS', 'reports': reports, 'negativeReceiptsNotCounted': failed_receipts,
        'validatorSelfTestReceiptsNotCounted': self_test_receipts}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--exclude-validator-self-tests', action='store_true',
        help='exclude only top-level check-dwarfdump and validation-evidence-controls fixtures')
    args = parser.parse_args()
    result = verify(args.root.resolve(strict=True), args.exclude_validator_self_tests)
    if args.output:
        args.output.write_text(json.dumps(result, indent=4) + '\n')
    print('retained-validator-reports=PASS reports=' + str(len(result['reports'])) +
        ' negative-receipts-not-counted=' + str(result['negativeReceiptsNotCounted']) +
        ' validator-self-test-receipts-not-counted=' + str(len(result['validatorSelfTestReceiptsNotCounted'])))


if __name__ == '__main__':
    main()
