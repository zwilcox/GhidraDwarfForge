# Windows directory-flush experiment for #72

**PRESENT, UNVERIFIED on Windows:** `src/test/native/windows-directory-flush.c`
and the existing native metadata harness now retain actual directory-open and
flush results. The probe cross-compiles with warnings treated as errors and
the PowerShell harness parses locally. Native execution remains required.

The unanswered question is whether an opened ordinary directory can be flushed
through the Win32 API under the caller's existing token, before and after the
opened-stage rename used by attachment. This experiment does not implement a
production host or select a filesystem durability contract.

Microsoft documents that [FlushFileBuffers requires a handle with GENERIC_WRITE](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers).
Its separately documented whole-volume flush requires administrative access.
[Directory handles require FILE_FLAG_BACKUP_SEMANTICS](https://learn.microsoft.com/en-us/windows/win32/fileio/obtaining-a-handle-to-a-directory).
Neither statement alone proves that this transaction's directory publication
survives power loss. `REPLACEFILE_WRITE_THROUGH` remains unsupported; a successful
file flush or namespace rename must not silently substitute for directory
durability.

The native probe:

- Exclusively creates a fresh owned directory and a five-byte file. Existing
  directories are refused before any file access or mutation.
- Records opened-directory 128-bit identity and volume/filesystem facts.
- Checks ordinary writable-file flushing and a read-only-file refusal.
- Observes directory opens with attributes-only, write-plus-attributes and
  read/write access, always with no leaf reparse traversal. It records success
  or the exact open/flush error; a refusal is not converted to success.
- Renames only its newly created child through `FileRenameInfo`, checks the
  resulting bytes, and repeats directory observations.
- Repeats all three access cases 128 times and requires exact process-handle
  equality after each cycle. It never opens a volume or changes privileges.

The PowerShell harness retains the current token privilege listing, raw child
output, commands, source hashes and SDK pin. An independent C# observer checks
the directory identity. The existing-directory refusal must preserve the
created child and its metadata. The probe leaves its owned evidence files for
artifact review.

Acceptance of this experiment requires a native Windows run, independently
reviewed output and exact source provenance. Its status is `OBSERVED`, even
when the control assertions pass. The next implementation decision must use
the actual results plus the documented filesystem behavior; process-kill tests
alone cannot prove power-loss recovery. Public attachment, full metadata
admission and the original A1–A7 requirements remain incomplete.
