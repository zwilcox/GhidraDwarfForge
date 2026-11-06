// Drive real native frame exports, deterministic rebasing and staged failure controls.
// @category DWARF.Tests
import ghidra.app.script.GhidraScript;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.WrappingTaskMonitor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CancellationException;

public class RecoveredFrameExportControls extends GhidraScript {
    @Override protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 4) throw new IllegalArgumentException("libdwarf libdwarfp output-directory failed-source-name");
        Path directory = Path.of(args[2]);
        for (String compression : List.of("none", "zlib")) {
            Path output = directory.resolve(compression + ".dbg");
            String[] options = {args[0], args[1], output.toString(), compression, "0", args[3]};
            runScript("ExportRecoveredFrames.java", options);
            byte[] artifact = Files.readAllBytes(output), source = Files.readAllBytes(Path.of(output + ".c"));
            byte[] evidence = Files.readAllBytes(Path.of(output + ".unwind.json"));
            runScript("ExportRecoveredFrames.java", options);
            requireSame(output, artifact, source);
            requireEvidence(output, evidence);
            Files.write(directory.resolve("before-rebase-" + compression + ".dbg"), artifact);
            Files.write(directory.resolve("before-rebase-" + compression + ".dbg.c"), source);
            Files.write(directory.resolve("before-rebase-" + compression + ".dbg.unwind.json"), evidence);
        }
        runScript("ExportRecoveredFrames.java", new String[] {args[0], args[1], directory.resolve("none.dbg").toString(), "none", "0x400000", args[3]});
        // Rebasing changes decompiler literals in some terminal instructions.
        // Require deterministic bytes for each unchanged program; the external
        // consumer separately checks identical original-image frame rules.
        for (String compression : List.of("none", "zlib")) {
            Path output = directory.resolve(compression + ".dbg");
            String[] options = {args[0], args[1], output.toString(), compression, "0", args[3]};
            if (compression.equals("zlib")) runScript("ExportRecoveredFrames.java", options);
            byte[] artifact = Files.readAllBytes(output), source = Files.readAllBytes(Path.of(output + ".c"));
            byte[] evidence = Files.readAllBytes(Path.of(output + ".unwind.json"));
            runScript("ExportRecoveredFrames.java", options);
            requireSame(output, artifact, source);
            requireEvidence(output, evidence);
        }
        byte[] plain = Files.readAllBytes(directory.resolve("none.dbg"));
        byte[] plainSource = Files.readAllBytes(directory.resolve("none.dbg.c"));
        byte[] plainEvidence = Files.readAllBytes(directory.resolve("none.dbg.unwind.json"));

        for (String stage : List.of("ghidradwarfforge.dwarf.DwarfDebugFrame", "ghidradwarfforge.output.UnwindEvidenceJson")) {
            for (boolean failure : List.of(false, true)) {
                TaskMonitor saved = monitor;
                int[] polls = {0};
                monitor = new WrappingTaskMonitor(saved) {
                    @Override public synchronized boolean isCancelled() {
                        if (super.isCancelled()) return true;
                        if (polls[0] == 5) return !failure;
                        if (StackWalker.getInstance().walk(frames -> frames.anyMatch(frame ->
                                frame.getClassName().equals(stage))) && ++polls[0] == 5) {
                            if (failure) throw new InjectedFailure();
                            return true;
                        }
                        return false;
                    }
                };
                boolean caught = false;
                try {
                    runScript("ExportRecoveredFrames.java", new String[] {args[0], args[1], directory.resolve("none.dbg").toString(), "none", "0", args[3]});
                }
                catch (CancellationException expected) { if (failure) throw expected; caught = true; }
                catch (InjectedFailure expected) { if (!failure) throw expected; caught = true; }
                finally { monitor = saved; }
                if (!caught || polls[0] != 5) throw new AssertionError("native frame control did not reach frame serialization");
                requireSame(directory.resolve("none.dbg"), plain, plainSource);
                requireEvidence(directory.resolve("none.dbg"), plainEvidence);
                try (var paths = Files.list(directory)) {
                    if (paths.anyMatch(path -> path.getFileName().toString().startsWith("."))) throw new AssertionError("native frame control leaked staging files");
                }
                println("native-frame-staging-control=PASS stage=" + stage + " failure=" + failure);
            }
        }
        runScript("ExportRecoveredFrames.java", new String[] {args[0], args[1], directory.resolve("none.dbg").toString(), "none", "0", args[3]});
        requireSame(directory.resolve("none.dbg"), plain, plainSource);
        requireEvidence(directory.resolve("none.dbg"), plainEvidence);
        println("native-frame-export-controls=PASS successful=9 controls=4");
    }

    private static void requireSame(Path output, byte[] artifact, byte[] source) throws Exception {
        if (!Arrays.equals(artifact, Files.readAllBytes(output)) || !Arrays.equals(source, Files.readAllBytes(Path.of(output + ".c")))) {
            throw new AssertionError("repeated/rebased export or failure changed the artifact generation");
        }
    }
    private static final class InjectedFailure extends IllegalStateException {
        InjectedFailure() { super("controlled native frame failure"); }
    }
    private static void requireEvidence(Path output, byte[] expected) throws Exception {
        if (!Arrays.equals(expected, Files.readAllBytes(Path.of(output + ".unwind.json")))) {
            throw new AssertionError("repeated export or failure changed unwind evidence");
        }
    }
}
