package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.CancellationException;

public final class CompanionArtifactPublisherSmoke {
    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("forge-companion-publisher-");
        try {
            for (boolean existing : List.of(false, true)) {
                for (int failAfter = -2; failAfter < 3; failAfter++) {
                    exercise(root, existing, failAfter);
                }
            }
            rejectAliases(root);
            preserveConcurrentChange(root);
            checkedCancellation(root);
            System.out.println("companion-artifact-publisher-smoke=PASS");
        }
        finally {
            try (var files = Files.walk(root)) {
                for (Path path : files.sorted(Comparator.reverseOrder()).toList()) {
                    Files.delete(path);
                }
            }
        }
    }

    private static void exercise(Path root, boolean existing, int failAfter) throws Exception {
        Path directory = Files.createDirectory(root.resolve(existing + "-" + failAfter));
        Path input = Files.writeString(directory.resolve("target"), "original");
        Path sidecar = directory.resolve("target.dbg");
        Path source = directory.resolve("target.dbg.c");
        Path companion = directory.resolve("target.dbg.gdb.py");
        List<Path> outputs = List.of(sidecar, source, companion);
        if (existing) {
            for (Path output : outputs) {
                Files.writeString(output, "old:" + output.getFileName());
            }
        }
        boolean[] installed = {false};
        try {
            CompanionArtifactPublisher.stageAndPublish(input, sidecar, source, companion,
                (a, b, c) -> {
                    if (!a.getParent().equals(directory) || !b.getParent().equals(directory)) {
                        throw new AssertionError("source directory would refer to private staging");
                    }
                    Files.writeString(a, "new-sidecar");
                    Files.writeString(b, "new-source");
                    if (failAfter == -2) {
                        throw new IOException("generation failed");
                    }
                    Files.writeString(c, "new-companion");
                }, () -> {
                    if (installed[0] && failAfter == 2) {
                        throw new CancellationException("cancelled after complete installation");
                    }
                }, index -> {
                    installed[0] = index == 2;
                    if (index == failAfter && index != 2) {
                        throw new IOException("injected install failure " + index);
                    }
                });
            if (failAfter != -1) {
                throw new AssertionError("expected injected failure");
            }
        }
        catch (IOException | CancellationException expected) {
            if (failAfter == -1 || expected.getSuppressed().length != 0) {
                throw expected;
            }
        }
        if (!Files.readString(input).equals("original")) {
            throw new AssertionError("original was changed");
        }
        for (Path output : outputs) {
            if (failAfter == -1) {
                if (!Files.readString(output).startsWith("new-")) {
                    throw new AssertionError("new generation missing");
                }
            }
            else if (existing) {
                if (!Files.readString(output).equals("old:" + output.getFileName())) {
                    throw new AssertionError("previous generation not restored");
                }
            }
            else if (Files.exists(output)) {
                throw new AssertionError("partial new generation remained");
            }
        }
        try (var children = Files.list(directory)) {
            if (children.anyMatch(path -> path.getFileName().toString().startsWith(".forge-"))) {
                throw new AssertionError("successful recovery leaked staging");
            }
        }
    }

    private static void rejectAliases(Path root) throws Exception {
        Path directory = Files.createDirectory(root.resolve("aliases"));
        Path input = Files.writeString(directory.resolve("input"), "original");
        Path output = Files.writeString(directory.resolve("output"), "sidecar");
        Path alias = Files.createLink(directory.resolve("alias"), input);
        for (Path companion : List.of(input, output, alias)) {
            try {
                CompanionArtifactPublisher.stageAndPublish(input, output, directory.resolve("source"), companion,
                    (a, b, c) -> { throw new AssertionError("writer ran before alias rejection"); }, () -> { });
                throw new AssertionError("alias accepted");
            }
            catch (IOException expected) {
                if (!expected.getMessage().contains("alias")) {
                    throw expected;
                }
            }
        }
        if (!Files.readString(input).equals("original") || !Files.readString(output).equals("sidecar")) {
            throw new AssertionError("alias preflight changed inputs");
        }
        Path library = Files.writeString(directory.resolve("native-library"), "native sentinel");
        try {
            CompanionArtifactPublisher.validate(input, output, directory.resolve("source"), library, library);
            throw new AssertionError("protected native input alias accepted");
        }
        catch (IOException expected) {
            if (!expected.getMessage().contains("protected input")) {
                throw expected;
            }
        }
    }

    private static void checkedCancellation(Path root) throws Exception {
        Path directory = Files.createDirectory(root.resolve("checked-cancellation"));
        Path input = Files.writeString(directory.resolve("input"), "original");
        Path sidecar = directory.resolve("sidecar");
        Files.write(sidecar, new byte[512 * 1024]);
        var expected = new Exception("checked monitor cancellation");
        int[] calls = {0};
        try {
            CompanionArtifactPublisher.stageAndPublish(input, sidecar, directory.resolve("source"),
                directory.resolve("companion"), (a, b, c) -> {
                    throw new AssertionError("writer ran after cancellation while observing old bytes");
                }, () -> {
                    if (++calls[0] == 5) {
                        throw expected;
                    }
                });
            throw new AssertionError("checked cancellation was ignored");
        }
        catch (Exception observed) {
            if (observed != expected) {
                throw observed;
            }
        }
        if (Files.size(sidecar) != 512 * 1024 || !Files.readString(input).equals("original")) {
            throw new AssertionError("cancellation modified previous generation");
        }
        try (var children = Files.list(directory)) {
            if (children.count() != 2) {
                throw new AssertionError("cancelled observation created outputs");
            }
        }
    }

    private static void preserveConcurrentChange(Path root) throws Exception {
        Path directory = Files.createDirectory(root.resolve("concurrent"));
        Path input = Files.writeString(directory.resolve("input"), "original");
        Path sidecar = Files.writeString(directory.resolve("output"), "old");
        try {
            CompanionArtifactPublisher.stageAndPublish(input, sidecar, directory.resolve("source"),
                directory.resolve("companion"), (a, b, c) -> {
                    Files.writeString(a, "new");
                    Files.writeString(b, "source");
                    Files.writeString(c, "companion");
                }, () -> { }, index -> {
                    if (index == 0) {
                        Files.writeString(sidecar, "concurrent user bytes");
                        throw new IOException("injected failure");
                    }
                });
            throw new AssertionError("expected failure");
        }
        catch (IOException expected) {
            if (expected.getSuppressed().length < 2) {
                throw new AssertionError("missing recovery diagnostics", expected);
            }
        }
        if (!Files.readString(sidecar).equals("concurrent user bytes")) {
            throw new AssertionError("rollback overwrote concurrent data");
        }
        try (var paths = Files.walk(directory)) {
            Path backup = paths.filter(path -> path.getFileName().toString().equals("backup-0"))
                .findFirst().orElseThrow();
            if (!Files.readString(backup).equals("old")) {
                throw new AssertionError("verified previous output not retained");
            }
        }
    }
}
