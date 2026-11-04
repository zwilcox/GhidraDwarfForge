package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/** Real native owner + actual JVM cancellation; no fake supervisor success. */
public final class ValidatorSupervisorSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        if (args.length != 3) throw new IllegalArgumentException("supply helper python new-results-directory");
        Path root = Path.of(args[2]).toAbsolutePath();
        Files.createDirectory(root);
        Path script = root.resolve("validator with spaces é.py");
        Files.writeString(script, """
            import json, os, signal, subprocess, sys, time
            from pathlib import Path
            mode = sys.argv[1]
            marker = Path(sys.argv[2])
            if mode == 'ok':
                print(json.dumps(sys.argv[3:]))
            elif mode == 'cwd':
                print(os.getcwd())
            elif mode == 'error':
                sys.exit(9)
            elif mode == 'flood':
                while True:
                    os.write(1, b'x' * 16384)
            elif mode == 'leaf':
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
                marker.write_text(str(os.getpid()))
                while True:
                    time.sleep(.01)
            else:
                child = subprocess.Popen([sys.executable, __file__, 'leaf', str(marker)],
                                         start_new_session=os.name != 'nt', close_fds=False)
                while not marker.exists():
                    time.sleep(.01)
                if mode == 'orphan':
                    sys.exit(0)
                while True:
                    time.sleep(.01)
            """);
        var runner = new ValidatorSupervisor(Path.of(args[0]));
        Path python = Path.of(args[1]);
        var success = runner.run(python, List.of(script.toString(), "ok", root.resolve("unused").toString(), "", "é", "a b", "quote\"slash\\"),
            root, Duration.ofSeconds(5), 65536, () -> false);
        require(success.status().cleanupComplete(), "successful cleanup not established");
        require(Files.readString(success.stdout()).contains("a b"), "argument with space lost");
        require(success.stderrDigest().byteCount() == 0, "unexpected stderr");
        require(success.stdoutDigest().equals(FileDigests.read(success.stdout())), "retained evidence digest differs");
        Path deep = root;
        while (deep.toString().length() < 310) {
            deep = Files.createDirectory(deep.resolve("long evidence é " + "x".repeat(40)));
        }
        var longPaths = runner.run(python, List.of(script.toString(), "cwd", root.resolve("unused").toString()),
            deep, Duration.ofSeconds(5), 65536, () -> false);
        require(longPaths.directory().getParent().equals(deep), "long evidence was relocated");
        require(Files.isSameFile(Path.of(Files.readString(longPaths.stdout()).strip()),
            ValidatorSupervisor.workingDirectory(longPaths.directory())), "validator working directory differs");
        require(longPaths.status().cleanupComplete() && longPaths.stderrDigest().byteCount() == 0,
            "long-path execution or cleanup failed");
        Path longCancel = root.resolve("long-cancel.pid");
        try {
            runner.run(python, List.of(script.toString(), "hang", longCancel.toString()), deep,
                Duration.ofSeconds(5), 4096, () -> Files.exists(longCancel));
            throw new AssertionError("long-path cancelled validator succeeded");
        }
        catch (ValidatorSupervisor.Cancelled expected) {
            require(expected.directory().getParent().equals(deep), "cancel evidence was relocated");
            require(ValidatorSupervisor.readStatus(expected.directory().resolve("status.json")).cleanupComplete(),
                "long-path cancellation did not clean up");
        }
        absent(longCancel);
        for (String mode : List.of("error", "flood", "orphan", "hang")) {
            Path marker = root.resolve(mode + ".pid");
            try {
                runner.run(python, List.of(script.toString(), mode, marker.toString()), root,
                    Duration.ofMillis(mode.equals("hang") ? 1500 : 5000), 4096, () -> false);
                throw new AssertionError("unsafe validator succeeded: " + mode);
            }
            catch (ValidatorSupervisor.Failure expected) {
                require(expected.evidence() != null && expected.evidence().status().cleanupComplete(), "failure did not clean up");
                String reason = switch (mode) {
                    case "error" -> "tool_error";
                    case "flood" -> "output_limit";
                    case "orphan" -> "descendants";
                    default -> "timeout";
                };
                require(expected.evidence().status().reason().equals(reason), "wrong failure reason");
                require(Files.size(expected.evidence().stdout()) <= 4096, "unbounded output");
            }
            absent(marker);
        }
        Path marker = root.resolve("cancel.pid");
        try {
            runner.run(python, List.of(script.toString(), "hang", marker.toString()), root,
                Duration.ofSeconds(5), 4096, () -> Files.exists(marker));
            throw new AssertionError("cancelled validator succeeded");
        }
        catch (ValidatorSupervisor.Cancelled expected) {
            require(ValidatorSupervisor.readStatus(expected.directory().resolve("status.json")).cleanupComplete(), "cancel did not clean up");
        }
        absent(marker);
        Path callbackMarker = root.resolve("callback.pid");
        try {
            runner.run(python, List.of(script.toString(), "hang", callbackMarker.toString()), root,
                Duration.ofSeconds(5), 4096, () -> {
                    if (Files.exists(callbackMarker)) throw new IllegalStateException("fixture callback failure");
                    return false;
                });
            throw new AssertionError("failed cancellation callback was ignored");
        }
        catch (ValidatorSupervisor.Failure expected) {
            require(expected.evidence() != null && expected.evidence().status().cleanupComplete() &&
                expected.getCause() instanceof IllegalStateException, "callback failure lost cleanup or cause");
        }
        absent(callbackMarker);
        Path interruptedMarker = root.resolve("interrupt.pid");
        AtomicReference<Throwable> threadResult = new AtomicReference<>();
        Thread thread = new Thread(() -> {
            try {
                runner.run(python, List.of(script.toString(), "hang", interruptedMarker.toString()), root,
                    Duration.ofSeconds(5), 4096, () -> false);
                threadResult.set(new AssertionError("interrupted validation succeeded"));
            }
            catch (ValidatorSupervisor.Cancelled expected) {
                if (!Thread.currentThread().isInterrupted()) threadResult.set(new AssertionError("interrupt status lost"));
            }
            catch (Throwable failure) { threadResult.set(failure); }
        });
        thread.start();
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (!Files.exists(interruptedMarker) && thread.isAlive() && System.nanoTime() < deadline) Thread.sleep(10);
        require(Files.exists(interruptedMarker), "interrupt child did not start");
        thread.interrupt();
        thread.join(9000);
        require(!thread.isAlive() && threadResult.get() == null, "interrupt cleanup failed: " + threadResult.get());
        absent(interruptedMarker);
        String valid = "{\"schemaVersion\":1,\"reason\":\"completed\",\"exitCode\":0,\"exitSignal\":0,\"cleanupComplete\":true," +
            "\"stdoutObserved\":0,\"stdoutRetained\":0,\"stderrObserved\":0,\"stderrRetained\":0}";
        Path report = root.resolve("status-control.json");
        for (String invalid : List.of(valid.replace("true", "\"true\""), valid.replace("\"exitCode\":0", "\"exitCode\":0,\"exitCode\":0"),
                valid.replace("\"stdoutObserved\":0", "\"stdoutObserved\":-1"), valid.replace("\"stdoutRetained\":0", "\"stdoutRetained\":1"),
                valid + "{}", valid.replace("completed", "unknown"), " ".repeat(4097))) {
            Files.writeString(report, invalid);
            try { ValidatorSupervisor.readStatus(report); throw new AssertionError("invalid status accepted"); }
            catch (IOException expected) { checks++; }
        }
        System.out.println("validator-supervisor-java=PASS checks=" + checks + " java=" + Runtime.version().feature());
    }

    private static void absent(Path marker) throws Exception {
        if (Files.exists(marker)) {
            long pid = Long.parseLong(Files.readString(marker));
            require(ProcessHandle.of(pid).map(process -> !process.isAlive()).orElse(true), "descendant survived: " + pid);
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }
}
