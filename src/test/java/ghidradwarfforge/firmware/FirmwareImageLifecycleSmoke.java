package ghidradwarfforge.firmware;

import ghidradwarfforge.output.FileDigests;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

/** Actual files and temporary carriers; no native producer or filesystem mocks. */
public final class FirmwareImageLifecycleSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("forge-firmware-lifecycle-");
        try {
            exercise(root);
        }
        finally {
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
        System.out.println("firmware-image-lifecycle=PASS checks=" + checks);
    }

    private static void exercise(Path root) throws Exception {
        byte[] original = new byte[96];
        for (int i = 0; i < original.length; i++) original[i] = (byte) (i * 3 + 1);
        Path input = Files.write(root.resolve("firmware.bin"), original);
        var captured = new FirmwareMemoryMap.Input("flash", original.length, FileDigests.read(input).sha256());
        var regions = List.of(new FirmwareMemoryMap.Region("code", 0x08004000, 32, true, false, true,
            FirmwareMemoryMap.Storage.FILE_BACKED, List.of(new FirmwareMemoryMap.FileSpan(0, 32, "flash", 16))),
            new FirmwareMemoryMap.Region("ram", 0x20000000, 16, true, true, false,
                FirmwareMemoryMap.Storage.UNINITIALIZED, List.of()));
        var map = new FirmwareMemoryMap(32, List.of(captured), regions);
        Set<Path> before = carriers();
        var checkpoints = new AtomicInteger();
        byte[] first;
        Path witness;
        try (var image = FirmwareExportImage.open(FirmwareTarget.CORTEX_M3, map, Map.of("flash", input), () -> {
            checkpoints.incrementAndGet();
            return false;
        })) {
            witness = image.witnessPath();
            first = Files.readAllBytes(witness);
            // Independently decode ELF32 section fields and compare the original
            // file slice, not a second invocation of the production parser.
            var bytes = ByteBuffer.wrap(first).order(ByteOrder.LITTLE_ENDIAN);
            int section = bytes.getInt(32) + 40;
            int offset = bytes.getInt(section + 16);
            require(bytes.getInt(section + 12) == 0x08004000 && bytes.getInt(section + 20) == 32,
                "file offset confused with mapped address");
            require(Arrays.equals(Arrays.copyOfRange(first, offset, offset + 32),
                Arrays.copyOfRange(original, 16, 48)), "witness bytes differ from mapped input slice");
            image.requireInputsUnchanged(() -> false);
            image.requireSafeOutput(root.resolve("new.dbg"));
            reject(() -> image.requireSafeOutput(input), "aliases an original");
            Path hard = Files.createLink(root.resolve("input-hardlink"), input);
            Path symbolic = Files.createSymbolicLink(root.resolve("input-symlink"), input);
            reject(() -> image.requireSafeOutput(hard), "aliases an original");
            reject(() -> image.requireSafeOutput(symbolic), "aliases an original");
            byte[] changed = original.clone();
            changed[0] ^= 1;
            Files.write(input, changed);
            reject(() -> image.requireInputsUnchanged(() -> false), "differs from captured provenance");
            require(Arrays.equals(changed, Files.readAllBytes(input)), "provenance check rewrote input");
            Files.write(input, original);
        }
        require(!Files.exists(witness.getParent()), "successful close leaked carrier files");
        require(checkpoints.get() > 10, "fixture did not reach image construction checkpoints");
        for (int stop = 1; stop <= checkpoints.get(); stop++) {
            int selected = stop;
            var observed = new AtomicInteger();
            try (var unexpected = FirmwareExportImage.open(FirmwareTarget.CORTEX_M3, map,
                    Map.of("flash", input), () -> observed.incrementAndGet() == selected)) {
                throw new AssertionError("ignored construction cancellation at " + stop);
            }
            catch (CancellationException expected) {
                require(observed.get() == stop, "late construction cancellation");
            }
            require(before.equals(carriers()), "cancelled construction leaked private carriers");
            require(Arrays.equals(original, Files.readAllBytes(input)), "cancelled construction changed original");
        }
        reject(() -> open(map, Map.of()), "missing firmware input path");
        reject(() -> open(map, Map.of("flash", input, "unexpected", input)), "differ from the captured map");
        reject(() -> open(new FirmwareMemoryMap(64, List.of(captured), regions), Map.of("flash", input)),
            "width or region count");
        Files.write(input, Arrays.copyOf(original, original.length - 1));
        reject(() -> open(map, Map.of("flash", input)), "differs from captured provenance");
        require(Files.size(input) == original.length - 1, "failed open rewrote truncated input");
        Files.write(input, original);
        try (var retry = FirmwareExportImage.open(FirmwareTarget.CORTEX_M3, map, Map.of("flash", input), () -> false)) {
            require(Arrays.equals(first, Files.readAllBytes(retry.witnessPath())), "retry changed deterministic witness");
        }
        require(before.equals(carriers()), "failed open or retry leaked private carriers");
        require(Arrays.equals(original, Files.readAllBytes(input)), "input bytes changed");
    }

    private static void open(FirmwareMemoryMap map, Map<String, Path> inputs) throws Exception {
        try (var ignored = FirmwareExportImage.open(FirmwareTarget.CORTEX_M3, map, inputs, () -> false)) { }
    }

    private static Set<Path> carriers() throws IOException {
        try (var paths = Files.list(Path.of(System.getProperty("java.io.tmpdir")))) {
            return paths.filter(path -> path.getFileName().toString().startsWith("forge-firmware-image-"))
                .collect(Collectors.toSet());
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }

    private interface Attempt { void run() throws Exception; }

    private static void reject(Attempt action, String diagnostic) throws Exception {
        try { action.run(); }
        catch (IOException | IllegalArgumentException expected) {
            require(expected.getMessage().contains(diagnostic), "wrong refusal: " + expected);
            return;
        }
        throw new AssertionError("accepted invalid firmware image operation: " + diagnostic);
    }
}
