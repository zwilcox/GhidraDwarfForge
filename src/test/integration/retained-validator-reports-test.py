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
    receipts = [p for p in sorted(args.root.rglob('*.check.json'))
        if json.loads(p.read_text())['status'] == 'PASS']
    assert receipts, 'a real passing validator receipt is required'
    source = receipts[0]
    source_raw = source.with_name(source.name.removesuffix('.check.json'))
    helper = Path(__file__).with_name('retained-validator-reports.py')
    cases = ('intact', 'empty', 'wrapper-overwrite', 'truncated-tail', 'receipt-mismatch', 'missing-raw')
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
            result = subprocess.run([sys.executable, helper, root], capture_output=True, text=True, timeout=30)
            if case == 'intact':
                assert result.returncode == 0 and 'retained-validator-reports=PASS reports=1' in result.stdout
                assert not result.stderr
            else:
                assert result.returncode != 0 and str(receipt.resolve()) in result.stderr, (case, result.stderr)
                assert 'retained-validator-reports=PASS' not in result.stdout
    print('retained-validator-reports-test=PASS positive=1 rejected=5')


if __name__ == '__main__':
    main()
