# Test code coverage and CI badges

The README's **Java test coverage** badge measures automated test execution.
It is separate from the exporter’s per-function source/type/variable evidence
coverage scorecards. A high test percentage is not proof of correct exported
DWARF, architecture support or debugger behavior.

## What is measured

The Linux `extension-build` job in `.github/workflows/ci.yml` enables JaCoCo
0.8.16 for the Gradle `JavaExec` test tasks it runs. Each task gets its own
execution-data file and completion record. The detailed report lists the actual
completed tasks, source commit, CI run, covered/missed lines and XML hash.
The complete JaCoCo HTML report is available in that run's `test-code-coverage`
artifact for 14 days; the public Markdown report retains per-source-file totals.

The metric is **covered executable Java lines / all executable Java lines**, as
reported by JaCoCo, rounded to one decimal place. Every compiled production class
under `src/main/java` is in the report population, including classes not loaded
by those tests. Test classes and Ghidra/dependency classes are outside the
population. JaCoCo's standard generated-bytecode filters apply. Files containing
only constants/interfaces can have no executable lines and are shown as not
applicable; they are never assigned 100%.

The following are not instrumented:

- Native C code, libdwarf and the Ghidra native decompiler.
- Python, shell and `ghidra_scripts` code.
- Independently launched headless Ghidra, subprocess JVMs and other integration
  lanes. Production Java classes reached only by these lanes remain in the
  denominator but may appear uncovered here.
- Windows execution and target-specific native/QEMU debugger execution.

Those tests remain part of the existing required validation matrix. This badge
adds a measurement; it does not replace any structural or behavior test, add an
arbitrary percentage threshold, or weaken `required-validation`.

## Publication

PR runs produce provisional report artifacts without repository write access.
Only a successful `push` run for `main`, after `required-validation` succeeds,
can publish the badge and detailed report. The publication job alone receives
`contents: write`. It regenerates the public files from the measured XML and
test manifest, checks commit/run/repository provenance, and skips superseded
main commits. It never publishes a PR's percentage as main coverage.

A normal commit updates three generated files on the dedicated
`reports/test-coverage` branch: `README.md`, `summary.json` and
`test-coverage.svg`. It preserves existing history and unrelated branch files;
there is no force push, main-branch generated-file commit, Pages deployment or
third-party coverage account. Concurrent publishers are serialized. The source
branch and coverage report branch have separate purposes; keep this report
branch when cleaning up merged feature branches.

The badge shows the **last fully validated main measurement**. The linked report
identifies that exact source commit and run. Failed/newer runs do not overwrite
it. Missing/incomplete task execution data, malformed counters, zero measured
population or mismatched public files fail report/publication checks instead of
producing a full-coverage badge. Before the first successful publication the
coverage badge/report may be unavailable; this is not a measured percentage.
GitHub's image cache can briefly lag an update.

The adjacent CI badge uses GitHub's live production workflow badge with
`branch=main&event=push`; it links to those same filtered workflow runs. Its
workflow status includes the supported architecture/host jobs. The coverage
percentage alone makes no statement that a newer main commit passed.

## Local reproduction

Local instrumentation is opt-in and requires the usual Ghidra/Java baseline.
Choose the tests explicitly; tasks requiring fixture/native arguments are not
implicitly launched by the reporting task:

```bash
python3 support/storage-guard.py run --cwd "$PWD" -- \
    ./gradlew --no-daemon -PtestCoverage=true \
    addressNormalizerSmoke inheritanceModelSmoke cxxProfileSmoke testCoverageReport
```

This example measures **only three tests**, not the whole CI population. The
XML and HTML are written under `build/test-coverage`; raw execution data is in
`build/jacoco`. Start with a clean owned build workspace when changing revisions
or measuring a different population. Do not combine execution data from other
commits. Ordinary builds without `-PtestCoverage=true` attach no coverage agent
and package no JaCoCo library.

`support/test-coverage-report.py` converts the XML and task manifest into the
public report. `support/publish-test-coverage.py --dry-run` regenerates and
verifies those files without contacting GitHub. Live publication is restricted
to the main CI job; do not fabricate run IDs or publish a partial local test
population as the main result.

Implementation references: [Gradle JaCoCo plugin](https://docs.gradle.org/current/userguide/jacoco_plugin.html),
[JaCoCo release history](https://www.jacoco.org/jacoco/trunk/doc/changes.html), and
[GitHub workflow status badges](https://docs.github.com/en/actions/how-tos/monitor-workflows/add-a-status-badge).

To verify a published measurement, follow the badge to its detailed report and
check the source commit, CI run, XML hash and completed-task population. Compare
the SVG percentage with the report counters and confirm that the linked run's
full required gate passed. A PR artifact verifies collection and rendering; it
does not establish that a main measurement has been published. The live main
badge and report links must also be checked after publication.
