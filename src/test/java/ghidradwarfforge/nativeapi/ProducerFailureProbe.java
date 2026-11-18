package ghidradwarfforge.nativeapi;

import com.sun.jna.Library;
import com.sun.jna.Native;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import ghidradwarfforge.source.SyntheticSourceFile;
import ghidradwarfforge.source.SyntheticSourceFile.FunctionText;
import ghidradwarfforge.source.SyntheticSourceFile.RelativeLine;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.TypeGraph;

/** Isolated-JVM fault controls around the actual pinned native producer. */
public final class ProducerFailureProbe {
    public interface Controls extends Library {
        void forge_test_mode(String mode);
        long forge_test_starts();
        long forge_test_finishes();
        long forge_test_finish_attempts();
        long forge_test_faults();
    }

    private ProducerFailureProbe() { }

    public static void main(String[] args) throws Exception {
        if (args.length != 8) throw new IllegalArgumentException(
            "consumer shim input output-directory address size fault expected-message");
        Path consumer = Path.of(args[0]), shim = Path.of(args[1]), input = Path.of(args[2]);
        Path directory = Files.createDirectory(Path.of(args[3]));
        Path output = directory.resolve("fixture.dbg");
        Path sourcePath = directory.resolve("fixture.dbg.c");
        long address = Long.decode(args[4]), size = Long.decode(args[5]);
        String mode = args[6], expected = args[7];
        byte[] inputBytes = Files.readAllBytes(input);
        var inputAttributes = Files.readAttributes(input, BasicFileAttributes.class);
        var source = SyntheticSourceFile.build("native-failure-fixture", "test",
            List.of(new FunctionText("forge_probe", address,
                "int forge_probe(int value)\n{\n  return value + 7;\n}\n", null,
                List.of(new RelativeLine(3, List.of(address))))));
        Files.write(sourcePath, source.utf8());
        var type = new TypeGraph.TypeRef("probe:int");
        var types = new TypeGraph(List.of(new TypeGraph.BaseType(type.key(), "int", 4,
            TypeGraph.BaseEncoding.SIGNED)));
        var signature = new ProgramTypeModel.FunctionSignature("forge_probe", address, type,
            List.of(new TypeGraph.Parameter("value", type, false)), List.of(),
            false, false, "default", "TEST_FIXTURE");
        var model = new ProgramTypeModel(types, List.of(signature), List.of());
        var functions = List.of(new MinimalDwarfSidecarExporter.FunctionSymbol("forge_probe", address, size));
        var exporter = new MinimalDwarfSidecarExporter();
        Controls controls = Native.load(shim.toString(), Controls.class);
        controls.forge_test_mode("control");
        exporter.export(input, output, consumer, shim, functions, source, model);
        byte[] baseline = Files.readAllBytes(output);
        var before = Files.readAttributes(output, BasicFileAttributes.class);
        require(controls.forge_test_starts() == 1 && controls.forge_test_finishes() == 1,
            "baseline must use and finish the real producer");
        for (boolean existing : new boolean[] { true, false }) {
            if (!existing) Files.delete(output);
            controls.forge_test_mode(mode);
            try {
                exporter.export(input, output, consumer, shim, functions, source, model);
                throw new AssertionError("fault was accepted: " + mode);
            }
            catch (IllegalStateException rejected) {
                require(rejected.getMessage().contains(expected),
                    "wrong rejection for " + mode + ": " + rejected);
            }
            require(controls.forge_test_starts() == controls.forge_test_finishes(),
                "native producer handle unfinished after " + mode);
            require(Files.exists(output) == existing, "failure published or deleted a final artifact");
            if (existing) {
                require(Arrays.equals(baseline, Files.readAllBytes(output)), "existing sidecar changed");
                var after = Files.readAttributes(output, BasicFileAttributes.class);
                require(Objects.equals(before.fileKey(), after.fileKey()) &&
                    before.lastModifiedTime().equals(after.lastModifiedTime()), "existing sidecar replaced");
            }
            try (var paths = Files.list(directory)) {
                require(paths.count() == (existing ? 2 : 1), "failed export left a staging file");
            }
            require(Arrays.equals(inputBytes, Files.readAllBytes(input)), "original input changed");
            var inputAfter = Files.readAttributes(input, BasicFileAttributes.class);
            require(Objects.equals(inputAttributes.fileKey(), inputAfter.fileKey()) &&
                inputAttributes.lastModifiedTime().equals(inputAfter.lastModifiedTime()), "original input replaced");
            require(Arrays.equals(source.utf8(), Files.readAllBytes(sourcePath)), "source companion changed");
        }
        require(controls.forge_test_faults() == 2, "both negative attempts must reach the selected fault");
        controls.forge_test_mode("control");
        exporter.export(input, output, consumer, shim, functions, source, model);
        require(Arrays.equals(baseline, Files.readAllBytes(output)), "retry differs after native failure");
        long expectedStarts = mode.startsWith("init-") ? 2 : 4;
        require(controls.forge_test_starts() == expectedStarts && controls.forge_test_finishes() == expectedStarts,
            "unexpected producer lifecycle count");
        require(controls.forge_test_finish_attempts() == expectedStarts + (mode.equals("finish-error") ? 2 : 0),
            "cleanup was skipped or repeated unexpectedly");
        System.out.println("producer-failure=PASS mode=" + mode + " faults=2 starts=" + expectedStarts +
            " finished=" + expectedStarts + " existing-preserved=true absent-preserved=true retry-identical=true");
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
