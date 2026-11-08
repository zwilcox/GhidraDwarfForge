// Exercises production export cancellation after original-file copying has begun.
// @category DWARF.Tests

import ghidra.app.script.GhidraScript;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.WrappingTaskMonitor;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.concurrent.CancellationException;

public class CancelDuringElfCopy extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2 || args.length > 3 ||
                (args.length == 3 && !args[2].equals("--gdb-loader"))) {
            throw new IllegalArgumentException("usage: <original ELF> <sidecar output> [--gdb-loader]");
        }
        Path input = Path.of(args[0]);
        Path artifact = Path.of(args[1]);
        Path source = Path.of(args[1] + ".c");
        byte[] oldArtifact = Files.readAllBytes(artifact);
        byte[] oldSource = Files.readAllBytes(source);
        boolean loader = args.length == 3;
        Path companion = Path.of(args[1] + ".gdb.py");
        byte[] oldCompanion = loader ? Files.readAllBytes(companion) : null;
        TaskMonitor originalMonitor = monitor;
        CopyMonitor copyMonitor = new CopyMonitor(originalMonitor, artifact.getParent());
        boolean cancelled = false;
        try {
            monitor = copyMonitor;
            // runScript passes this monitor to the real installed entry point.
            var options = new java.util.ArrayList<>(java.util.List.of("--packaged-natives",
                "--input", input.toString(), "--output", artifact.toString()));
            if (loader) {
                options.add("--gdb-loader");
            }
            runScript("GhidraDwarfForge.java", options.toArray(String[]::new));
        }
        catch (CancellationException expected) {
            cancelled = true;
        }
        finally {
            monitor = originalMonitor;
        }
        if (!cancelled || copyMonitor.copiedBytes <= 0 ||
                copyMonitor.copiedBytes > 16L * 1024 * 1024 ||
                copyMonitor.copiedBytes >= Files.size(input)) {
            throw new AssertionError("production export did not cancel during bounded copying");
        }
        if (!Arrays.equals(oldArtifact, Files.readAllBytes(artifact)) ||
                !Arrays.equals(oldSource, Files.readAllBytes(source)) ||
                (loader && !Arrays.equals(oldCompanion, Files.readAllBytes(companion)))) {
            throw new AssertionError("cancelled export modified the existing artifact generation");
        }
        try (var files = Files.list(artifact.getParent())) {
            if (files.anyMatch(path -> path.getFileName().toString().startsWith("."))) {
                throw new AssertionError("cancelled export left temporary or backup files");
            }
        }
        println("copy-cancelled-after-bytes=" + copyMonitor.copiedBytes);
        println("production-copy-cancellation=PASS");
    }

    private static final class CopyMonitor extends WrappingTaskMonitor {
        private final Path directory;
        private long copiedBytes;

        private CopyMonitor(TaskMonitor delegate, Path directory) {
            super(delegate);
            this.directory = directory;
        }

        @Override
        public synchronized boolean isCancelled() {
            if (copiedBytes > 0 || super.isCancelled()) {
                return true;
            }
            try (var files = Files.list(directory)) {
                Path temporary = files.filter(path -> path.getFileName().toString()
                    .startsWith(".ghidra-dwarf-forge-")).findFirst().orElse(null);
                if (temporary != null) {
                    copiedBytes = Files.size(temporary);
                }
                return copiedBytes > 0;
            }
            catch (IOException failure) {
                throw new UncheckedIOException(failure);
            }
        }
    }
}
