package ghidradwarfforge.firmware;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CancellationException;

import ghidradwarfforge.annotations.SyntheticConstants;
import ghidradwarfforge.elf.CortexM3Profile;
import ghidradwarfforge.elf.ElfFunctionModeCue;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.output.FileDigests;
import ghidradwarfforge.source.SyntheticSourceFile;
import ghidradwarfforge.source.SyntheticSourceFile.FunctionText;
import ghidradwarfforge.source.SyntheticSourceFile.RelativeLine;

/** Isolated native process: real raw bytes, checked synthetic carriers and production DWARF. */
public final class FirmwareExportSmoke {
    public static void main(String[] args) throws Exception {
        Path root = Path.of(args[2]);
        Files.createDirectory(root);
        Path input = root.resolve("firmware.bin");
        byte[] raw = new byte[128];
        raw[24] = 0x70;
        raw[25] = 0x47; // Thumb BX LR, with a nonzero original-file offset.
        raw[72] = 7;
        Files.write(input, raw);
        String sha = FileDigests.read(input).sha256();
        String codeSha = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
            .digest(new byte[] {0x70, 0x47}));
        var inputs = List.of(new FirmwareMemoryMap.Input("firmware", raw.length, sha));
        int checks = 0;
        for (long base : new long[] {0x100, 0x08004100}) {
            String name = "raw-" + Long.toHexString(base);
            var map = new FirmwareMemoryMap(32, inputs, List.of(
                new FirmwareMemoryMap.Region("flash", base, 32, true, false, true,
                    FirmwareMemoryMap.Storage.FILE_BACKED,
                    List.of(new FirmwareMemoryMap.FileSpan(0, 32, "firmware", 24))),
                new FirmwareMemoryMap.Region("data", 0x20000000, 4, true, true, false,
                    FirmwareMemoryMap.Storage.FILE_BACKED,
                    List.of(new FirmwareMemoryMap.FileSpan(0, 4, "firmware", 72))),
                new FirmwareMemoryMap.Region("unknown", 0x20000004, 4, true, true, false,
                    FirmwareMemoryMap.Storage.UNINITIALIZED, List.of())));
            Path sidecar = root.resolve(name + ".dbg");
            var source = SyntheticSourceFile.build("firmware.bin", "ARM:LE:32:Cortex", List.of(
                new FunctionText("recovered", base, "void recovered(void) {\n    return;\n}\n", null,
                    List.of(new RelativeLine(2, List.of(base))))));
            Path sourcePath = root.resolve(name + ".dbg.c");
            source.writeAtomically(sourcePath);
            Path witness;
            try (var image = FirmwareExportImage.open(FirmwareTarget.CORTEX_M3, map,
                    Map.of("firmware", input), () -> false)) {
                witness = image.witnessPath();
                requireCarrier(image.witness(), false);
                requireCarrier(image.allocations(), true);
                CortexM3Profile.requireImage(image.witness(), () -> false);
                byte[] bytes = Files.readAllBytes(witness);
                var encoded = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
                int first = encoded.getInt(32) + 40;
                int offset = encoded.getInt(first + 16);
                if (Integer.toUnsignedLong(encoded.getInt(first + 12)) != base || bytes[offset] != 0x70 ||
                        bytes[offset + 1] != 0x47) throw new AssertionError("witness address/offset mismatch");
                var exporter = new MinimalDwarfSidecarExporter();
                var symbols = List.of(new FunctionSymbol("recovered", base, 2));
                var cues = List.of(new ElfFunctionModeCue("recovered", base, 2, base | 1, codeSha));
                for (int iteration = 0; iteration < 2; iteration++) {
                    byte[] previous = Files.exists(sidecar) ? Files.readAllBytes(sidecar) : null;
                    var exported = exporter.exportFirmware(image, sidecar, Path.of(args[0]), Path.of(args[1]),
                        symbols, source, null, sourcePath.getFileName().toString(), () -> false,
                        cues, List.of(), List.of(), List.of(), new SyntheticConstants(List.of(), Set.of()),
                        message -> { throw new AssertionError("unexpected omission: " + message); }, null);
                    if (exported.functionCount() != 1) throw new AssertionError("function lost");
                    requireCarrier(ElfImage.read(sidecar), true);
                    if (previous != null && !Arrays.equals(previous, Files.readAllBytes(sidecar))) {
                        throw new AssertionError("nondeterministic firmware sidecar");
                    }
                    checks++;
                }
                byte[] good = Files.readAllBytes(sidecar);
                try {
                    exporter.exportFirmware(image, input, Path.of(args[0]), Path.of(args[1]),
                        symbols, source, null, sourcePath.getFileName().toString(), () -> false,
                        cues, List.of(), List.of(), List.of(), new SyntheticConstants(List.of(), Set.of()),
                        ignored -> { }, null);
                    throw new AssertionError("input overwrite accepted");
                }
                catch (java.io.IOException expected) {
                    if (!expected.getMessage().contains("aliases an original")) throw expected;
                    checks++;
                }
                try {
                    exporter.exportFirmware(image, sidecar, Path.of(args[0]), Path.of(args[1]),
                        symbols, source, null, sourcePath.getFileName().toString(), () -> true,
                        cues, List.of(), List.of(), List.of(), new SyntheticConstants(List.of(), Set.of()),
                        ignored -> { }, null);
                    throw new AssertionError("cancelled export completed");
                }
                catch (CancellationException expected) { checks++; }
                if (!Arrays.equals(good, Files.readAllBytes(sidecar))) throw new AssertionError("cancel changed previous output");
            }
            if (Files.exists(witness.getParent())) throw new AssertionError("temporary firmware carrier leaked");
            checks++;
        }
        if (!Arrays.equals(raw, Files.readAllBytes(input))) throw new AssertionError("original raw bytes changed");
        System.out.println("firmware-production-export=PASS checks=" + checks);
    }

    private static void requireCarrier(ElfImage image, boolean inert) throws Exception {
        var header = ByteBuffer.wrap(image.headerBytes()).order(ByteOrder.LITTLE_ENDIAN);
        if (image.is64Bit() || image.machine() != 40 || image.type() != 2 ||
                header.getInt(24) != 0 || header.getInt(28) != 0 || header.getShort(44) != 0 ||
                !image.segments().isEmpty()) {
            throw new AssertionError("synthetic container acquired executable identity");
        }
        var encoded = ByteBuffer.wrap(image.bytes()).order(ByteOrder.LITTLE_ENDIAN);
        for (int i = 0; i < Short.toUnsignedInt(header.getShort(48)); i++) {
            int section = header.getInt(32) + i * 40;
            int type = encoded.getInt(section + 4);
            int flags = encoded.getInt(section + 8);
            if (type == 7 || inert && (flags & 2) != 0 && type != 8) {
                throw new AssertionError("synthetic firmware has original identity or loadable contents");
            }
        }
    }
}
