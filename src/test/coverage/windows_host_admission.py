"""Common rejection cases for Windows-only primitive evidence."""


class WindowsHostCases:
    def test_actual_windows_required(self):
        record, evidence = self.fixture()
        for key, value in [('suite', 'fake'), ('layer', 'javaexec'), ('host', 'posix')]:
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'actual Windows'):
                self.oracle({**record, key: value}, evidence)
        with self.assertRaisesRegex(ValueError, 'actual Windows'):
            self.oracle(record, {**evidence, 'status': 'FAILED'})
