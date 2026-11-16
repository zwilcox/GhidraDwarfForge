#!/usr/bin/env python3
"""Pinned GDB transport retries, integrity and staging ownership; no network/build."""
import contextlib
import errno
import http.client
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location('build_mips_gdb', ROOT / 'support/validation/build-mips-gdb.py')
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)
ABC_SHA256 = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'


class Interrupted(io.BytesIO):
    def read(self, size=-1):
        if self.tell():
            raise http.client.IncompleteRead(b'', 1)
        return super().read(size)


class DownloadTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='forge-gdb-download-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.archive = self.root / 'gdb.tar.xz'
        self.pin = patch.object(builder, 'ARCHIVE_SHA256', ABC_SHA256)
        self.pin.start()
        self.addCleanup(self.pin.stop)

    def exercise(self, responses, expected_calls, error=None):
        with patch.object(builder.urllib.request, 'urlopen', side_effect=responses) as opening, \
                patch.object(builder.time, 'sleep') as sleeping, contextlib.redirect_stdout(io.StringIO()) as log:
            if error:
                with self.assertRaises(error):
                    builder.download_archive(self.archive)
                self.assertFalse(self.archive.exists())
                self.assertEqual([], list(self.root.iterdir()))
            else:
                builder.download_archive(self.archive)
                self.assertEqual(b'abc', self.archive.read_bytes())
                self.assertEqual([self.archive], list(self.root.iterdir()))
            self.assertEqual(expected_calls, opening.call_count)
            for call in opening.call_args_list:
                self.assertEqual((builder.URL,), call.args)
                self.assertEqual({'timeout': 60}, call.kwargs)
            self.assertEqual(expected_calls - 1, sleeping.call_count)
            self.assertEqual([2, 4][:expected_calls - 1], [call.args[0] for call in sleeping.call_args_list])
            return log.getvalue()

    def test_release_pin_unchanged(self):
        self.pin.stop()
        self.assertEqual('17.1', builder.VERSION)
        self.assertEqual('14996f5f74c9f68f5a543fdc45bca7800207f91f92aeea6c2e791822c7c6d876', builder.ARCHIVE_SHA256)
        self.assertEqual('https://ftp.gnu.org/gnu/gdb/gdb-17.1.tar.xz', builder.URL)

    def test_success(self):
        self.exercise([io.BytesIO(b'abc')], 1)

    def test_network_unreachable_then_success(self):
        log = self.exercise([urllib.error.URLError(OSError(errno.ENETUNREACH, 'Network is unreachable')),
            io.BytesIO(b'abc')], 2)
        self.assertIn('attempt 1/3 failed', log)

    def test_partial_response_is_discarded(self):
        self.exercise([Interrupted(b'ab'), io.BytesIO(b'abc')], 2)

    def test_timeout_then_reset_then_success(self):
        self.exercise([TimeoutError('timeout'), ConnectionResetError('reset'), io.BytesIO(b'abc')], 3)

    def test_exhausted_retries_leave_no_archive(self):
        self.exercise([urllib.error.URLError('offline')] * 3, 3, urllib.error.URLError)

    def test_wrong_digest_is_not_retried(self):
        self.exercise([io.BytesIO(b'abx')], 1, ValueError)

    def test_oversized_response_is_not_retried(self):
        with patch.object(builder, 'MAX_ARCHIVE_BYTES', 2):
            self.exercise([io.BytesIO(b'abc')], 1, ValueError)

    def test_empty_response_is_not_retried(self):
        self.exercise([io.BytesIO(b'')], 1, ValueError)

    def test_interruption_cleans_staging(self):
        self.exercise([KeyboardInterrupt()], 1, KeyboardInterrupt)

    def test_existing_archive_is_preserved(self):
        self.archive.write_bytes(b'keep')
        with patch.object(builder.urllib.request, 'urlopen') as opening:
            with self.assertRaises(FileExistsError):
                builder.download_archive(self.archive)
            opening.assert_not_called()
        self.assertEqual(b'keep', self.archive.read_bytes())

    def test_dangling_link_is_preserved(self):
        self.archive.symlink_to('missing')
        with patch.object(builder.urllib.request, 'urlopen') as opening:
            with self.assertRaises(FileExistsError):
                builder.download_archive(self.archive)
            opening.assert_not_called()
        self.assertEqual(Path('missing'), self.archive.readlink())

    def test_concurrently_created_destination_is_preserved(self):
        def response(*args, **kwargs):
            self.archive.write_bytes(b'other caller')
            return io.BytesIO(b'abc')
        with patch.object(builder.urllib.request, 'urlopen', side_effect=response), \
                patch.object(builder.time, 'sleep') as sleeping:
            with self.assertRaises(FileExistsError):
                builder.download_archive(self.archive)
            sleeping.assert_not_called()
        self.assertEqual(b'other caller', self.archive.read_bytes())
        self.assertEqual([self.archive], list(self.root.iterdir()))

    def test_filesystem_failure_is_not_retried(self):
        with patch.object(builder.os, 'link', side_effect=OSError(errno.ENOSPC, 'full')):
            self.exercise([io.BytesIO(b'abc')], 1, OSError)


if __name__ == '__main__':
    unittest.main(verbosity=2)
