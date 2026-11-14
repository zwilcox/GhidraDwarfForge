# Windows supervisor pipe regression

`windows-supervisor-pipe-eof.c` includes the production supervisor translation
unit and calls its actual `drain` function. The test intercepts only the
availability query to control writer-exit timing; pipe reads, writes, closure,
process creation and termination use native Windows APIs.

Run on native Windows with MinGW GCC:

```powershell
python src/test/integration/windows-supervisor-pipe.py `
    --compiler C:/msys64/mingw64/bin/gcc.exe --results build/pipe-regression
```

The results directory must be new. Each case has a bounded subprocess deadline
and retains its output and exit status. CI runs these checks in the required
native Windows build, before packaging the supervisor.

- `race`: a 64-KiB write remains pending on a 4-KiB pipe. After a successful
  availability query, terminate and wait for the writer before the production
  read. The read can now report `ERROR_BROKEN_PIPE`. Require successful EOF,
  a closed reader, unchanged byte counters, an empty log and repeatable EOF.
- `data` / `capped`: read known bytes, check exact retained content and counts,
  then require EOF. The capped case must report output exceeding its limit.
- `bad-read`: close the reader after a successful availability query. The real
  `ReadFile` must fail with `ERROR_INVALID_HANDLE`; require failure, not EOF.
- `bad-log`: pass an invalid log handle while reading a valid pipe. Require
  write failure without claiming retained bytes or successful EOF.

The original implementation failed the controlled race on Windows in
[run 43638962297](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/43638962297):
`intercepted=1 snapshot=65536 drained=0 eof=0 observed=0 error=109`.
Two separate 500-iteration uncontrolled flood runs did not reproduce it;
repetition alone is not the regression oracle.

These tests do not replace the existing `validator-supervisor.py` process/job
ownership tests or the JVM cancellation smoke test. Successful cleanup still
requires the root process to exit, an empty job and EOF on both output streams.
