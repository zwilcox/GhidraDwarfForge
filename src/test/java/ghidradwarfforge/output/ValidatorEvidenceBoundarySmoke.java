package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.List;

/** Negative helper-protocol controls; these never establish native cleanup success. */
final class ValidatorEvidenceBoundarySmoke {
    private ValidatorEvidenceBoundarySmoke() { }

    static void run(Path python, Path parent) throws Exception {
        if (!System.getProperty("os.name").equals("Linux")) {
            System.out.println("validator-evidence-rejections=NOT_RUN requires Linux executable scripts");
            return;
        }
        Path root = Files.createDirectory(parent.resolve("evidence-rejections"));
        String interpreter = python.toRealPath().toString();
        if (interpreter.chars().anyMatch(Character::isWhitespace)) {
            throw new IllegalArgumentException("fixture interpreter cannot contain shebang whitespace");
        }
        String body = """
            import json, os, sys
            from pathlib import Path
            mode = Path(__file__).parent.name
            status, out, err = map(Path, sys.argv[3:6])
            tool = Path(sys.argv[7])
            value = dict(schemaVersion=1, reason='completed', exitCode=0, exitSignal=0,
                         cleanupComplete=True, stdoutObserved=0, stdoutRetained=0,
                         stderrObserved=0, stderrRetained=0)
            out.write_bytes(b'')
            err.write_bytes(b'')
            if mode == 'missing-status':
                sys.exit(0)
            if mode in ('stdout-mismatch', 'stderr-mismatch'):
                (out if mode.startswith('stdout') else err).write_bytes(b'x')
            if mode in ('stdout-over-cap', 'stderr-over-cap'):
                stream = 'stdout' if mode.startswith('stdout') else 'stderr'
                (out if stream == 'stdout' else err).write_bytes(b'x' * 17)
                value[stream + 'Observed'] = value[stream + 'Retained'] = 17
            if mode == 'cleanup-incomplete':
                value['cleanupComplete'] = False
            if mode == 'cancelled-status':
                value['reason'] = 'cancelled'
            if mode == 'tool-exit':
                value['exitCode'] = 9
            if mode == 'tool-signal':
                value['exitSignal'] = 9
            if mode in ('changed-helper', 'changed-tool'):
                changed = Path(__file__) if mode == 'changed-helper' else tool
                with changed.open('a') as stream:
                    stream.write('\\n# changed fixture bytes\\n')
            status.write_text(json.dumps(value))
            if mode == 'helper-stdout':
                print('fixture setup diagnostic')
            if mode == 'helper-stderr':
                print('fixture setup diagnostic', file=sys.stderr)
            sys.exit(7 if mode == 'helper-exit' else 0)
            """;
        int checks = 0;
        for (String mode : List.of("helper-stdout", "helper-stderr", "missing-status",
                "stdout-mismatch", "stderr-mismatch", "stdout-over-cap", "stderr-over-cap",
                "changed-helper", "changed-tool", "cleanup-incomplete", "cancelled-status",
                "helper-exit", "tool-exit", "tool-signal", "launch-failure")) {
            Path directory = Files.createDirectory(root.resolve(mode));
            Path helper = directory.resolve("helper.py");
            Files.writeString(helper, mode.equals("launch-failure")
                ? "#!/forge-test-missing-interpreter\n" : "#!" + interpreter + "\n" + body);
            Files.setPosixFilePermissions(helper, PosixFilePermissions.fromString("rwx------"));
            Path tool = directory.resolve("selected-tool");
            Files.writeString(tool, "#!/bin/sh\nexit 0\n");
            Files.setPosixFilePermissions(tool, PosixFilePermissions.fromString("rwx------"));
            var runner = new ValidatorSupervisor(helper);
            try {
                runner.run(tool, List.of(), directory, Duration.ofSeconds(5), 16, () -> false);
                throw new AssertionError("invalid helper evidence accepted: " + mode);
            }
            catch (ValidatorSupervisor.Cancelled expected) {
                require(mode.equals("cancelled-status"), "unrelated refusal became cancellation: " + mode);
                require(Files.isRegularFile(expected.directory().resolve("status.json")), "cancellation evidence lost");
            }
            catch (ValidatorSupervisor.Failure expected) {
                String reason = switch (mode) {
                    case "helper-stdout", "helper-stderr" -> "internal/setup failure";
                    case "missing-status" -> "evidence or supervision failed";
                    case "stdout-mismatch", "stderr-mismatch", "stdout-over-cap", "stderr-over-cap" -> "counters or bounds disagree";
                    case "changed-helper", "changed-tool" -> "changed during execution";
                    case "cleanup-incomplete" -> "process cleanup is incomplete";
                    case "launch-failure" -> "could not start";
                    default -> "process failed: completed";
                };
                require(expected.getMessage().contains(reason), "wrong refusal for " + mode + ": " + expected);
                require(expected.directory().getParent().equals(directory), "evidence escaped fixture directory");
                boolean reconciled = List.of("cleanup-incomplete", "helper-exit", "tool-exit", "tool-signal").contains(mode);
                require((expected.evidence() != null) == reconciled, "unreconciled evidence treated as valid: " + mode);
                if (mode.equals("missing-status")) {
                    require(expected.getCause() instanceof IOException, "missing status cause lost");
                }
                if (mode.equals("cleanup-incomplete")) {
                    require(!expected.evidence().status().cleanupComplete(), "incomplete cleanup claimed complete");
                }
            }
            checks++;
        }
        System.out.println("validator-evidence-rejections=PASS controls=" + checks + " scope=negative-helper-protocol");
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
