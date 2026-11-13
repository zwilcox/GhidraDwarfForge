// Real raw-export failure/cancellation controls on an unsaved read-only domain object.
// @category DWARF.Tests
import ghidra.app.script.GhidraScript;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.WrappingTaskMonitor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CancellationException;

public class CheckRawFirmwareFailures extends GhidraScript {
    private record Stage(String owner, String method, int stop) { }
    private int checks;
    private String selectionPath;

    @Override protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2 && args.length != 3) throw new IllegalArgumentException("original output [firmware-inputs]");
        selectionPath = args.length == 3 ? args[2] : null;
        Path original = Path.of(args[0]);
        Path artifact = Path.of(args[1]);
        var protectedPaths = List.of(original, artifact, Path.of(artifact + ".c"), Path.of(artifact + ".firmware.json"));
        var protectedBytes = new java.util.ArrayList<byte[]>();
        for (Path path : protectedPaths) protectedBytes.add(Files.readAllBytes(path));
        Path controls = artifact.getParent().resolve("raw-failure-controls");
        Files.createDirectory(controls);
        for (boolean existing : new boolean[] {false, true}) {
            Path output = controls.resolve(existing ? "existing.dbg" : "absent.dbg");
            if (existing) {
                Files.write(output, protectedBytes.get(1));
                Files.write(Path.of(output + ".c"), protectedBytes.get(2));
                Files.write(Path.of(output + ".firmware.json"), protectedBytes.get(3));
            }
            var before = inventory(controls);
            for (Stage stage : List.of(
                    new Stage("ghidradwarfforge.firmware.GhidraFirmwareMemoryMap", "capture", 3),
                    new Stage("ghidradwarfforge.firmware.FirmwareExportImage", "write", 5),
                    new Stage("ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter", "produce", 3),
                    new Stage("ghidradwarfforge.elf.MatchedElfSidecarWriter", "write", 5),
                    new Stage("ghidradwarfforge.firmware.GhidraFirmwareSession", "manifest", 3))) {
                TaskMonitor previous = monitor;
                var probe = new Probe(previous, stage);
                boolean cancelled = false;
                try {
                    monitor = probe;
                    runScript("GhidraDwarfForge.java", options(original, output));
                }
                catch (CancelledException | CancellationException expected) { cancelled = true; }
                finally { monitor = previous; }
                if (!cancelled || probe.polls != stage.stop()) throw new AssertionError("stage not cancelled: " + stage);
                if (!before.equals(inventory(controls))) throw new AssertionError("cancellation changed generation: " + stage);
                checks++;
            }
        }
        // All cancelled stages must release native resources and permit a deterministic retry.
        runScript("GhidraDwarfForge.java", options(original, artifact));
        for (int i = 0; i < protectedPaths.size(); i++) {
            if (!Arrays.equals(protectedBytes.get(i), Files.readAllBytes(protectedPaths.get(i)))) {
                throw new AssertionError("post-cancellation recovery changed " + protectedPaths.get(i));
            }
        }
        checks++;
        var memory = currentProgram.getMemory();
        var entry = currentProgram.getFunctionManager().getFunctions(true).next().getEntryPoint();
        Path output = controls.resolve("absent.dbg");
        // Ghidra forbids changing bytes under decoded instructions. Change a
        // file-backed data byte instead; the same provenance rule must reject it.
        var patched = memory.getBlock("ram-initialization").getStart();
        byte saved = memory.getByte(patched);
        memory.setByte(patched, (byte) (saved ^ 1));
        try { reject(original, output, controls, "analysis bytes differ"); }
        finally { memory.setByte(patched, saved); }
        var overlay = memory.createUninitializedBlock("invalid-overlay", entry, 4, true);
        try { reject(original, output, controls, "overlay, alias or unmapped"); }
        finally { memory.removeBlock(overlay, monitor); }
        var alias = memory.createByteMappedBlock("invalid-alias", toAddr(0x40000000), entry, 4, false);
        try { reject(original, output, controls, "overlay, alias or unmapped"); }
        finally { memory.removeBlock(alias, monitor); }
        var unbacked = memory.createInitializedBlock("unbacked", toAddr(0x40000000), 4, (byte) 0, monitor, false);
        try { reject(original, output, controls, "no original-file provenance"); }
        finally { memory.removeBlock(unbacked, monitor); }
        Path selection = controls.resolve("stale-inputs.json");
        Files.writeString(selection, "{\"schema\":1,\"inputs\":[{\"id\":\"raw\",\"fileBytesIndex\":999,\"path\":\"unused.bin\"}]}");
        reject(original, output, controls, "outside the current inventory", "--firmware-inputs=" + selection);
        Path collision = controls.resolve("collision.dbg");
        Path link = Path.of(collision + ".firmware.json");
        Files.createLink(link, original);
        try { reject(original, collision, controls, "alias"); }
        finally { Files.delete(link); }
        var locator = currentProgram.getDomainFile().getProjectLocator();
        reject(original, locator.getMarkerFile().toPath(), controls, "aliases a saved project file");
        reject(original, locator.getProjectDir().toPath().resolve("must-not-exist.dbg"), controls,
            "inside the saved project");
        Files.createLink(link, locator.getMarkerFile().toPath());
        try { reject(original, collision, controls, "aliases a saved project file"); }
        finally { Files.delete(link); }
        if (selectionPath != null) {
            Path descriptor = Path.of(selectionPath);
            var selected = ghidradwarfforge.output.FirmwareInputs.read(descriptor, monitor::isCancelled);
            Path extra = Path.of(selected.inputs().getLast().path());
            if (!extra.isAbsolute()) extra = descriptor.getParent().resolve(extra);
            byte[] extraBefore = Files.readAllBytes(extra);
            Files.createLink(link, extra);
            try { reject(original, collision, controls, "aliases a protected input"); }
            finally { Files.delete(link); }
            if (!Arrays.equals(extraBefore, Files.readAllBytes(extra))) throw new AssertionError("extra firmware input changed");
        }
        for (int i = 0; i < protectedPaths.size(); i++) {
            if (!Arrays.equals(protectedBytes.get(i), Files.readAllBytes(protectedPaths.get(i)))) {
                throw new AssertionError("failure controls changed " + protectedPaths.get(i));
            }
        }
        println("raw-firmware-failure-controls=PASS cases=" + checks);
    }

    private String[] options(Path original, Path output, String... extra) {
        var options = new java.util.ArrayList<>(List.of("--packaged-natives", "--raw-firmware=cortex-m3",
            "--input=" + original, "--output=" + output));
        if (selectionPath != null && Arrays.stream(extra).noneMatch(value -> value.startsWith("--firmware-inputs="))) {
            options.add("--firmware-inputs=" + selectionPath);
        }
        options.addAll(List.of(extra));
        return options.toArray(String[]::new);
    }

    private void reject(Path original, Path output, Path directory, String reason, String... extra) throws Exception {
        var before = inventory(directory);
        boolean rejected = false;
        try { runScript("GhidraDwarfForge.java", options(original, output, extra)); }
        catch (IllegalArgumentException | java.io.IOException expected) {
            if (!expected.getMessage().contains(reason)) throw expected;
            rejected = true;
        }
        if (!rejected || !before.equals(inventory(directory))) throw new AssertionError("invalid map changed generation: " + reason);
        checks++;
    }

    private static Map<String, String> inventory(Path directory) throws Exception {
        Map<String, String> result = new TreeMap<>();
        try (var paths = Files.walk(directory)) {
            for (Path path : paths.skip(1).toList()) {
                result.put(directory.relativize(path).toString(), Files.isRegularFile(path)
                    ? ghidradwarfforge.output.FileDigests.read(path).sha256() : "non-file");
            }
        }
        return result;
    }

    private static final class Probe extends WrappingTaskMonitor {
        private final Stage stage;
        private int polls;
        Probe(TaskMonitor delegate, Stage stage) { super(delegate); this.stage = stage; }
        @Override public synchronized boolean isCancelled() {
            if (polls >= stage.stop() || super.isCancelled()) return true;
            boolean inside = StackWalker.getInstance().walk(frames -> frames.anyMatch(frame ->
                frame.getClassName().equals(stage.owner()) && frame.getMethodName().equals(stage.method())));
            return inside && ++polls == stage.stop();
        }
        @Override public void checkCancelled() throws CancelledException {
            if (isCancelled()) throw new CancelledException();
        }
    }
}
