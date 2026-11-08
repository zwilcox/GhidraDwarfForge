// Cancels inside production compression, verifies pair preservation, then retries.
// @category DWARF.Tests

import ghidra.app.script.GhidraScript;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.WrappingTaskMonitor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.concurrent.CancellationException;

public class CancelDuringCompression extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) {
            throw new IllegalArgumentException("usage: <original ELF> <sidecar output>");
        }
        Path input = Path.of(args[0]);
        Path artifact = Path.of(args[1]);
        Path source = Path.of(args[1] + ".c");
        byte[] oldArtifact = Files.readAllBytes(artifact);
        byte[] oldSource = Files.readAllBytes(source);
        String[] options = { "--packaged-natives", "--compress-debug-sections=zlib",
            "--input", input.toString(), "--output", artifact.toString() };
        TaskMonitor originalMonitor = monitor;
        CompressionMonitor probe = new CompressionMonitor(originalMonitor);
        boolean cancelled = false;
        try {
            monitor = probe;
            runScript("GhidraDwarfForge.java", options);
        }
        catch (CancellationException expected) {
            cancelled = true;
        }
        finally {
            monitor = originalMonitor;
        }
        if (!cancelled || probe.polls != 5) {
            throw new AssertionError("export did not cancel during compression");
        }
        if (!Arrays.equals(oldArtifact, Files.readAllBytes(artifact)) ||
                !Arrays.equals(oldSource, Files.readAllBytes(source))) {
            throw new AssertionError("cancelled compression replaced the previous pair");
        }
        try (var files = Files.list(artifact.getParent())) {
            if (files.count() != 2) {
                throw new AssertionError("cancelled compression left temporary files");
            }
        }
        println("production-compression-cancellation=PASS polls=" + probe.polls);
        runScript("GhidraDwarfForge.java", options);
        if (Arrays.equals(oldArtifact, Files.readAllBytes(artifact)) ||
                Arrays.equals(oldSource, Files.readAllBytes(source))) {
            throw new AssertionError("retry did not publish a new artifact pair");
        }
        println("production-compression-retry=PASS");
    }

    private static final class CompressionMonitor extends WrappingTaskMonitor {
        private int polls;

        private CompressionMonitor(TaskMonitor delegate) {
            super(delegate);
        }

        @Override
        public synchronized boolean isCancelled() {
            if (polls >= 5 || super.isCancelled()) {
                return true;
            }
            boolean compressing = StackWalker.getInstance().walk(frames -> frames.anyMatch(frame ->
                frame.getClassName().equals("ghidradwarfforge.elf.DebugSectionCompression") &&
                    frame.getMethodName().equals("encode")));
            return compressing && ++polls == 5;
        }
    }
}
