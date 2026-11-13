// Real MMIO generation cancellation/failure and preservation controls.
// @category DWARF.Tests
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CancellationException;
import com.google.gson.JsonParser;
import ghidra.app.script.GhidraScript;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.WrappingTaskMonitor;
import ghidradwarfforge.GhidraMmioProfile;

public class CheckMmioFailures extends GhidraScript {
    private record Stage(String owner, String method, int stop) { }
    private int checks;
    private boolean raw;
    @Override protected void run() throws Exception {
        String[] args = getScriptArgs();
        if ((args.length != 3 && args.length != 4) || (args.length == 4 && !args[3].equals("raw"))) {
            throw new IllegalArgumentException("input output controls-directory [raw]");
        }
        raw = args.length == 4;
        Path original = Path.of(args[0]);
        Path artifact = Path.of(args[1]);
        var suffixes = new java.util.ArrayList<>(List.of("", ".c", ".mmio.json"));
        if (raw) suffixes.add(".firmware.json");
        var protectedPaths = new java.util.ArrayList<>(List.of(original));
        for (var suffix : suffixes) protectedPaths.add(Path.of(artifact + suffix));
        var hashes = new java.util.ArrayList<String>();
        for (var path : protectedPaths) hashes.add(ghidradwarfforge.output.FileDigests.read(path).sha256());
        Path controls = Path.of(args[2]);
        Files.createDirectory(controls);
        for (boolean existing : new boolean[] {false, true}) {
            Path output = controls.resolve(existing ? "existing.dbg" : "absent.dbg");
            if (existing) {
                for (String suffix : suffixes) {
                    Files.copy(Path.of(artifact + suffix), Path.of(output + suffix));
                }
            }
            var before = inventory(controls);
            var stages = new java.util.ArrayList<>(List.of(
                    new Stage("ghidradwarfforge.GhidraMmioProfile", "read", 2),
                    new Stage("ghidradwarfforge.GhidraMmioProfile", "contribute", 2),
                    new Stage("ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter", "produce", 3),
                    new Stage("ghidradwarfforge.elf.MatchedElfSidecarWriter", "write", 5),
                    new Stage("ghidradwarfforge.GhidraMmioProfile", "render", 2)));
            if (raw) stages.addAll(List.of(
                new Stage("ghidradwarfforge.firmware.GhidraFirmwareMemoryMap", "capture", 3),
                new Stage("ghidradwarfforge.firmware.FirmwareExportImage", "write", 5),
                new Stage("ghidradwarfforge.firmware.GhidraFirmwareSession", "manifest", 3)));
            for (var stage : stages) {
                TaskMonitor previous = monitor;
                var probe = new Probe(previous, stage);
                boolean cancelled = false;
                try { monitor = probe; runScript("GhidraDwarfForge.java", options(original, output)); }
                catch (CancelledException | CancellationException expected) { cancelled = true; }
                finally { monitor = previous; }
                if (!cancelled || probe.polls != stage.stop() || !before.equals(inventory(controls))) {
                    throw new AssertionError("MMIO cancellation failed preservation: " + stage);
                }
                checks++;
            }
        }
        // Retry before deliberately mutating selection metadata. Raw manifests
        // correctly record the in-memory modification number, even after a
        // temporary option is restored to its previous value.
        runScript("GhidraDwarfForge.java", options(original, artifact));
        for (int i = 0; i < protectedPaths.size(); i++) {
            if (!hashes.get(i).equals(ghidradwarfforge.output.FileDigests.read(protectedPaths.get(i)).sha256())) {
                throw new AssertionError("MMIO cancellation recovery changed " + protectedPaths.get(i));
            }
        }
        checks++;
        var savedOptions = currentProgram.getOptions(GhidraMmioProfile.OPTIONS);
        String selected = savedOptions.getString(GhidraMmioProfile.SELECTION, null);
        var template = JsonParser.parseString(selected).getAsJsonObject();
        String oversized = null;
        if (currentProgram.getDataTypeManager().getDataType("/uint") == null) throw new AssertionError("missing fixture unsigned base type");
        for (int pad : new int[] {50, 60, 65}) {
            var candidate = template.deepCopy();
            var registers = new com.google.gson.JsonArray();
            for (int i = 0; i < 128; i++) {
                var register = template.getAsJsonArray("registers").get(0).deepCopy().getAsJsonObject();
                register.addProperty("name", "register_" + i + "_" + "x".repeat(pad));
                for (int v = 0; v < register.getAsJsonArray("views").size(); v++) {
                    var view = register.getAsJsonArray("views").get(v).getAsJsonObject();
                    view.addProperty("name", "view_" + v + "_" + "x".repeat(pad));
                    view.addProperty("datatype", "/uint");
                    view.add("qualifiers", new com.google.gson.JsonArray());
                }
                registers.add(register);
            }
            candidate.add("registers", registers);
            String text = candidate.toString();
            if (text.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > 65536) continue;
            var profile = GhidraMmioProfile.read(currentProgram, text, monitor);
            try { profile.render(ghidradwarfforge.elf.ElfImage.read(artifact), artifact, () -> false); }
            catch (java.io.IOException expected) {
                if (!expected.getMessage().contains("rendered MMIO profile exceeds")) throw expected;
                oversized = text;
                break;
            }
        }
        if (oversized == null) throw new AssertionError("missing late profile-render failure fixture");
        savedOptions.setString(GhidraMmioProfile.SELECTION, oversized);
        try { reject(original, controls.resolve("existing.dbg"), controls, "rendered MMIO profile exceeds"); }
        finally { savedOptions.setString(GhidraMmioProfile.SELECTION, selected); }
        Path selection = controls.resolve("formatters.json");
        Files.writeString(selection, "{\"schema\":1,\"types\":[{\"key\":\"not-used\",\"mode\":\"structure\"}]}");
        reject(original, controls.resolve("absent.dbg"), controls, "without automatic formatters", "--formatters=" + selection);
        Path collision = controls.resolve("collision.dbg");
        Path link = Path.of(collision + ".mmio.json");
        Files.createLink(link, original);
        try { reject(original, collision, controls, "alias"); }
        finally { Files.delete(link); }
        var locator = currentProgram.getDomainFile().getProjectLocator();
        Files.createLink(link, locator.getMarkerFile().toPath());
        try { reject(original, collision, controls, "aliases a saved project file"); }
        finally { Files.delete(link); }
        reject(original, locator.getProjectDir().toPath().resolve("must-not-exist.dbg"), controls, "inside the saved project");
        for (int i = 0; i < protectedPaths.size(); i++) {
            if (!hashes.get(i).equals(ghidradwarfforge.output.FileDigests.read(protectedPaths.get(i)).sha256())) {
                throw new AssertionError("MMIO control/recovery changed " + protectedPaths.get(i));
            }
        }
        println("mmio-failure-controls=PASS checks=" + checks);
    }

    private String[] options(Path input, Path output, String... extra) {
        var result = new java.util.ArrayList<>(List.of("--packaged-natives", "--mmio", "--input=" + input, "--output=" + output));
        if (raw) result.add("--raw-firmware=cortex-m3");
        result.addAll(List.of(extra));
        return result.toArray(String[]::new);
    }
    private void reject(Path input, Path output, Path directory, String reason, String... extra) throws Exception {
        var before = inventory(directory);
        boolean rejected = false;
        try { runScript("GhidraDwarfForge.java", options(input, output, extra)); }
        catch (IllegalArgumentException | java.io.IOException expected) {
            if (!expected.getMessage().contains(reason)) throw expected;
            rejected = true;
        }
        if (!rejected || !before.equals(inventory(directory))) throw new AssertionError("MMIO failure changed outputs: " + reason);
        checks++;
    }
    private static Map<String, String> inventory(Path directory) throws Exception {
        Map<String, String> result = new TreeMap<>();
        try (var paths = Files.walk(directory)) {
            for (var path : paths.skip(1).toList()) {
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
