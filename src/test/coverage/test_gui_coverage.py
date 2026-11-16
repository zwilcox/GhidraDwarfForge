"""GUI receipt admission controls; synthetic files here do not establish desktop execution."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parents[1] / 'integration'
sys.path.insert(0, str(SCRIPTS))
try:
    spec = importlib.util.spec_from_file_location('gui_coverage_controls', SCRIPTS / 'gui-coverage.py')
    gui = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gui)
finally:
    sys.path.pop(0)


class GuiReceiptAdmission(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='forge-gui-receipt-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def normal(self):
        lines = ['installed-script-discovery=PASS', 'native-free-preflight-run=PASS',
            'script-manager-export-selection=PASS', 'script-manager-export-cancellation=PASS',
            'console-report-presentation=PASS', 'original-input-preservation=PASS',
            'script-manager-structural-validation=PASS', 'script-manager-gdb=PASS']
        (self.root / 'result.txt').write_text('\n'.join(lines) + '\n')
        return lines

    def test_mode_is_explicit_and_not_ambiguous(self):
        self.assertEqual(gui.selected_mode({}), 'default')
        for key, mode in gui.MODES.items():
            self.assertEqual(gui.selected_mode({key: '1'}), mode)
            with self.assertRaises(ValueError):
                gui.selected_mode({key: 'true'})
        with self.assertRaises(ValueError):
            gui.selected_mode({'GHIDRA_GUI_UNWIND': '1', 'GHIDRA_GUI_COMPRESSION': '1'})

    def test_export_alone_cannot_certify_complete_oracle(self):
        lines = self.normal()
        marker = 'gui-script-manager-integration=PASS\n'
        for mode in ('default', 'compressed', 'loader', 'native-attachment'):
            gui.verify_outcome(self.root, marker, mode)
        for missing in lines:
            (self.root / 'result.txt').write_text('\n'.join(line for line in lines if line != missing))
            with self.subTest(missing=missing), self.assertRaisesRegex(ValueError, 'complete debugger oracle'):
                gui.verify_outcome(self.root, marker, 'default')
        self.normal()
        for output in ('gui-script-manager=PASS\n', marker * 2, ''):
            with self.assertRaisesRegex(ValueError, 'complete debugger oracle'):
                gui.verify_outcome(self.root, output, 'default')

    def test_unwind_requires_all_four_validator_and_debugger_cases(self):
        (self.root / 'result.txt').write_text('installed-unwind-chooser=PASS\nchoices=7\nexports=4\ncancellations=3\n')
        marker = 'gui-unwind-structural-and-gdb=PASS\n'
        with self.assertRaisesRegex(ValueError, 'missing GUI unwind'):
            gui.verify_outcome(self.root, marker, 'unwind')
        result = {'status': 'PASS_GUI_UNWIND', 'cases': [{'mode': mode} for mode in
            ('off', 'strict', 'conditioned-no-pointers', 'conditioned-fixed')]}
        path = self.root / 'unwind-result.json'
        path.write_text(json.dumps(result))
        gui.verify_outcome(self.root, marker, 'unwind')
        for cases in (result['cases'][:-1], result['cases'][::-1], [result['cases'][0]] * 4):
            path.write_text(json.dumps({**result, 'cases': cases}))
            with self.assertRaisesRegex(ValueError, 'incomplete GUI unwind'):
                gui.verify_outcome(self.root, marker, 'unwind')

    def test_missing_oversized_or_linked_receipt_rejected(self):
        marker = 'gui-script-manager-integration=PASS\n'
        with self.assertRaisesRegex(ValueError, 'missing or excessive'):
            gui.verify_outcome(self.root, marker, 'default')
        self.normal()
        path = self.root / 'result.txt'
        saved = path.read_bytes()
        path.write_bytes(b'x' * 65537)
        with self.assertRaisesRegex(ValueError, 'missing or excessive'):
            gui.verify_outcome(self.root, marker, 'default')
        path.unlink()
        (self.root / 'other').write_bytes(saved)
        try:
            path.symlink_to(self.root / 'other')
        except OSError:
            return  # Windows privilege-independent missing/size checks still ran.
        with self.assertRaisesRegex(ValueError, 'missing or excessive'):
            gui.verify_outcome(self.root, marker, 'default')


if __name__ == '__main__':
    unittest.main()
