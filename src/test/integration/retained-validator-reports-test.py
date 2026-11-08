#!/usr/bin/env python3
"""Exercise post-validation report damage using a real completed checker report."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    args = parser.parse_args()
    source = next((p for p in sorted(args.root.rglob('*.check.json'))
        if p.relative_to(args.root).parts[0] not in ('check-dwarfdump', 'validation-evidence-controls') and
        json.loads(p.read_text())['status'] == 'PASS'), None)
    assert source is not None, 'a real passing validator receipt is required'
    source_raw = source.with_name(source.name.removesuffix('.check.json'))
    helper = Path(__file__).with_name('retained-validator-reports.py')
    cases = ('intact', 'empty', 'wrapper-overwrite', 'truncated-tail', 'receipt-mismatch', 'missing-raw',
        'malformed-production', 'checker-fixtures-default', 'checker-fixtures-excluded',
        'evidence-fixtures-default', 'evidence-fixtures-excluded',
        'nested-checker-directory', 'different-directory')
    with tempfile.TemporaryDirectory(prefix='forge-retained-validator-') as directory:
        for case in cases:
            root = Path(directory) / case
            root.mkdir()
            receipt, raw = root / 'strict.log.check.json', root / 'strict.log'
            shutil.copyfile(source, receipt)
            shutil.copyfile(source_raw, raw)
            shutil.copyfile(source_raw.with_name(source_raw.name + '.stderr'), root / 'strict.log.stderr')
            if case == 'empty':
                raw.write_text('')
            elif case == 'wrapper-overwrite':
                raw.write_text('strict-dwarfdump=PASS reported-errors=0\n')
            elif case == 'truncated-tail':
                raw.write_text(raw.read_text().rsplit('Number of TAG records', 1)[0])
            elif case == 'receipt-mismatch':
                metadata = json.loads(receipt.read_text())
                metadata['check_tables'] += 1
                receipt.write_text(json.dumps(metadata))
            elif case == 'missing-raw':
                raw.unlink()
            elif case == 'malformed-production':
                receipt.write_text('preserve original ELF control\n')
            excluded = case in ('checker-fixtures-excluded', 'nested-checker-directory', 'different-directory',
                'malformed-production', 'evidence-fixtures-excluded')
            expected_receipt = receipt
            if case in ('checker-fixtures-default', 'checker-fixtures-excluded',
                    'nested-checker-directory', 'different-directory',
                    'evidence-fixtures-default', 'evidence-fixtures-excluded'):
                folder = {'nested-checker-directory': 'exports/check-dwarfdump',
                    'different-directory': 'check-dwarfdump-extra',
                    'evidence-fixtures-default': 'validation-evidence-controls',
                    'evidence-fixtures-excluded': 'validation-evidence-controls'}.get(case, 'check-dwarfdump')
                expected_receipt = root / folder / 'run.example/alias-metadata-direct/checker.txt.check.json'
                expected_receipt.parent.mkdir(parents=True)
                if case.startswith('evidence-fixtures-'):
                    shutil.copyfile(source, expected_receipt)
                    damaged = expected_receipt.with_name('checker.txt')
                    damaged.write_text('')
                    damaged.with_name('checker.txt.stderr').write_text('')
                else:
                    expected_receipt.write_text('preserve original ELF control\n')
            command = [sys.executable, helper, root]
            if excluded:
                command.append('--exclude-validator-self-tests')
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            if case in ('intact', 'checker-fixtures-excluded', 'evidence-fixtures-excluded'):
                assert result.returncode == 0 and 'retained-validator-reports=PASS reports=1' in result.stdout
                assert not result.stderr
                assert 'validator-self-test-receipts-not-counted=' + str(int(excluded)) in result.stdout
            else:
                assert result.returncode != 0 and str(expected_receipt.resolve()) in result.stderr, (case, result.stderr)
                assert 'retained-validator-reports=PASS' not in result.stdout
    print('retained-validator-reports-test=PASS positive=3 rejected=10')


if __name__ == '__main__':
    main()
