"""Check mutation evidence classification; synthetic outcomes are not mutation evidence."""
import importlib.util
from pathlib import Path
import subprocess
import unittest


spec = importlib.util.spec_from_file_location('mutation_check', Path(__file__).with_name('mutation-check.py'))
mutation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mutation)


def result(code, text):
    return subprocess.CompletedProcess(['fixture'], code, text)


class MutationOutcomes(unittest.TestCase):
    def test_java_assertion_is_detection(self):
        self.assertEqual(mutation.verify_outcome('fixture', result(1, 'java.lang.AssertionError: wrong bytes'), True), 'java-assertion')

    def test_java_setup_failure_is_not_detection(self):
        for text in ('java.lang.IllegalArgumentException: fixture setup', 'ClassNotFoundException',
                     'java.lang.AssertionError: NoClassDefFoundError', 'LinkageError', 'java.lang.OutOfMemoryError'):
            with self.subTest(text=text), self.assertRaises(AssertionError):
                mutation.verify_outcome('fixture', result(1, text), True)

    def test_zero_exit_assertion_text_is_not_detection(self):
        with self.assertRaises(AssertionError):
            mutation.verify_outcome('fixture', result(0, 'java.lang.AssertionError: ignored'), True)

    def test_independent_numeric_assertion_is_detection(self):
        oracle = result(1, "Traceback (most recent call last):\nAssertionError: ({'expected': 'ff'}, '0')\n")
        self.assertEqual(mutation.verify_outcome('fixture', result(0, 'generation=PASS'), True, oracle),
                         'independent-dwarf-oracle-assertion')

    def test_oracle_setup_or_incomplete_data_is_not_detection(self):
        for text in ('FileNotFoundError: vectors.json', 'KeyError: expected', 'ValueError: malformed JSON',
                     'prefix AssertionError: misleading text', 'AssertionError: missing boundary/random profiles'):
            with self.subTest(text=text), self.assertRaises(AssertionError):
                mutation.verify_outcome('fixture', result(0, 'generation=PASS'), True, result(1, text))

    def test_oracle_must_follow_successful_generation(self):
        with self.assertRaises(AssertionError):
            mutation.verify_outcome('fixture', result(1, 'failed generation'), True, result(1, 'AssertionError: wrong bytes'))
        with self.assertRaises(AssertionError):
            mutation.verify_outcome('fixture', result(0, 'generation=PASS'), True, result(0, 'AssertionError: ignored'))

    def test_unchanged_baseline_requires_oracle_success(self):
        self.assertEqual(mutation.verify_outcome('fixture', result(0, 'generation=PASS'), False,
            result(0, 'call-value-dwarf-vm=PASS vectors=8000')), 'baseline-pass')
        for code, text in ((1, 'AssertionError: wrong bytes'), (0, 'no verification'), (1, 'call-value-dwarf-vm=PASS')):
            with self.subTest(code=code, text=text), self.assertRaises(AssertionError):
                mutation.verify_outcome('fixture', result(0, 'generation=PASS'), False, result(code, text))

    def test_passing_mutant_is_not_detection(self):
        with self.assertRaises(AssertionError):
            mutation.verify_outcome('fixture', result(0, 'generation=PASS'), True,
                result(0, 'call-value-dwarf-vm=PASS'))


if __name__ == '__main__':
    unittest.main()
