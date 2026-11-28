package evaluation;

import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.output.ArtifactPairPublisher.PrePublishCheck;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CancellationException;

/** A/B/A exports share the process, target, artifact path and generated source directory. */
final class LifecycleChecks {
    private static String strings(Path sidecar) throws IOException {
        var elf = ElfImage.read(sidecar);
        var section = elf.sections().stream().filter(s -> ".debug_str".equals(s.name())).findFirst().orElseThrow();
        return new String(elf.sectionData(section), StandardCharsets.UTF_8);
    }

    private static void same(byte[] expected, Path path) throws IOException {
        if (!Arrays.equals(expected, Files.readAllBytes(path))) throw new AssertionError("changed: " + path);
    }

    private static void failedPublication(EvaluationFixture model, String backend, Path input,
            Path output, Path libraries, boolean cancel) throws Exception {
        PrePublishCheck fail = () -> {
            if (cancel) throw new CancellationException("injected cancellation");
            throw new IOException("injected failed prepublication check");
        };
        try {
            model.export(backend, input, output, libraries, () -> false, fail);
        }
        catch (CancellationException expected) {
            if (!cancel || !"injected cancellation".equals(expected.getMessage())) throw expected;
            return;
        }
        catch (IOException expected) {
            if (cancel || !"injected failed prepublication check".equals(expected.getMessage())) throw expected;
            return;
        }
        throw new AssertionError("published after injected failure");
    }

    public static void main(String[] args) throws Exception {
        String backend = args[0];
        Path libraries = Path.of(args[1]);
        Path input = Path.of(args[2]);
        Path output = Path.of(args[3]);
        Path source = Path.of(output + ".c");
        byte[] original = Files.readAllBytes(input);
        long start = EvaluationFixture.hex(args[4]);
        long size = EvaluationFixture.hex(args[5]);
        long split = EvaluationFixture.hex(args[6]);
        long first = EvaluationFixture.hex(args[7]);
        long second = EvaluationFixture.hex(args[8]);
        long firstRangeEnd = EvaluationFixture.hex(args[9]);
        boolean x86Leaf = args[10].equals("x86_64");
        var a = new EvaluationFixture("first_unique_export_name", start, size, split, first, second, firstRangeEnd, true, x86Leaf);
        var b = new EvaluationFixture("second_unique_export_name", start, size, split, first, second, firstRangeEnd, true, x86Leaf);
        for (boolean cancel : List.of(true, false)) {
            failedPublication(b, backend, input, output, libraries, cancel);
            if (Files.exists(output) || Files.exists(source)) throw new AssertionError("partial new output");
            same(original, input);
        }
        a.export(backend, input, output, libraries, () -> false);
        byte[] bytes = Files.readAllBytes(output);
        byte[] text = Files.readAllBytes(source);
        b.export(backend, input, output, libraries, () -> false);
        String secondStrings = strings(output);
        if (secondStrings.contains(a.function()) || !secondStrings.contains(b.function())) {
            throw new AssertionError("string lifetime crossed A/B");
        }
        a.export(backend, input, output, libraries, () -> false);
        String firstStrings = strings(output);
        if (firstStrings.contains(b.function()) || !firstStrings.contains(a.function())) {
            throw new AssertionError("string lifetime crossed B/A");
        }
        same(bytes, output);
        same(text, source);
        for (boolean cancel : List.of(true, false)) {
            failedPublication(b, backend, input, output, libraries, cancel);
            same(bytes, output);
            same(text, source);
            same(original, input);
        }
        try (var siblings = Files.list(output.getParent())) {
            if (siblings.count() != 2) throw new AssertionError("staging files survived publication");
        }
        System.out.println("A/B/A, failed and cancelled publication PASS: " + backend);
    }
}
