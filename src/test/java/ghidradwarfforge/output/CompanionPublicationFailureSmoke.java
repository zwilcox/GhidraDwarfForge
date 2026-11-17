package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

/** Filesystem fault injection with byte and exception-identity oracles. */
public final class CompanionPublicationFailureSmoke {
    private static int cases;

    private CompanionPublicationFailureSmoke() { }

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("forge-publication-failures-");
        try {
            preflight(root);
            invalidStages(root);
            cleanupFailure(root, false);
            cleanupFailure(root, true);
            observationChange(root);
            symbolicOutputs(root);
            for (boolean existing : List.of(false, true)) cancellation(root, existing);
            System.out.println("companion-publication-failures=PASS cases=" + cases);
        }
        finally {
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
    }

    private static void preflight(Path root) throws Exception {
        Path dir = Files.createDirectory(root.resolve("preflight"));
        Path input = Files.writeString(dir.resolve("input"), "original");
        List<Path> outputs = outputs(dir);
        Path elsewhere = Files.createDirectory(dir.resolve("elsewhere"));
        Path directoryOutput = Files.createDirectory(dir.resolve("directory-output"));
        var selections = List.of(outputs.subList(0, 2),
            List.of(outputs.get(0), outputs.get(1), outputs.get(2), dir.resolve("four"), dir.resolve("five"), dir.resolve("six")),
            List.of(outputs.get(0), outputs.get(1), elsewhere.resolve("companion")),
            List.of(outputs.get(0), outputs.get(1), directoryOutput));
        for (List<Path> selected : selections) {
            refuse(() -> CompanionArtifactPublisher.stageAndPublish(input, selected,
                stages -> { throw new AssertionError("writer ran after invalid preflight"); }, () -> { }));
            noStages(dir);
        }
        for (Path invalidInput : List.of(dir.resolve("missing"), elsewhere)) {
            refuse(() -> CompanionArtifactPublisher.stageAndPublish(invalidInput, outputs,
                stages -> { throw new AssertionError("writer ran without a regular input"); }, () -> { }));
        }
        Path unrelated = Files.writeString(dir.resolve("unrelated"), "protected");
        CompanionArtifactPublisher.validate(input, outputs, unrelated);
        require(Files.readString(unrelated).equals("protected"), "validation changed unrelated input");
        require(Files.readString(input).equals("original"), "preflight changed original");
        require(outputs.stream().noneMatch(Files::exists), "preflight left outputs");
    }

    private static void invalidStages(Path root) throws Exception {
        for (String kind : List.of("missing", "directory", "symlink")) {
            Path dir = Files.createDirectory(root.resolve("invalid-" + kind));
            Path input = Files.writeString(dir.resolve("input"), "original");
            List<Path> outputs = outputs(dir);
            seed(outputs);
            refuse(() -> CompanionArtifactPublisher.stageAndPublish(input, outputs, stages -> {
                write(stages);
                Files.delete(stages.get(1));
                switch (kind) {
                    case "directory" -> Files.createDirectory(stages.get(1));
                    case "symlink" -> Files.createSymbolicLink(stages.get(1), input);
                    default -> { }
                }
            }, () -> { }));
            previous(outputs, true);
            require(Files.readString(input).equals("original"), "invalid stage modified input");
            noStages(dir);
        }
    }

    private static void cleanupFailure(Path root, boolean installed) throws Exception {
        Path dir = Files.createDirectory(root.resolve("cleanup-" + installed));
        Path input = Files.writeString(dir.resolve("input"), "original");
        List<Path> outputs = outputs(dir);
        seed(outputs);
        IOException primary = new IOException("injected writer failure");
        Path[] obstruction = { null };
        try {
            CompanionArtifactPublisher.stageAndPublish(input, outputs, stages -> {
                write(stages);
                if (!installed) {
                    Files.delete(stages.get(1));
                    Files.createDirectory(stages.get(1));
                    obstruction[0] = Files.writeString(stages.get(1).resolve("keep"), "recovery witness");
                    throw primary;
                }
            }, () -> { }, index -> {
                if (installed && index == 2) {
                    try (var paths = Files.list(dir)) {
                        Path recovery = paths.filter(path -> path.getFileName().toString().startsWith(".forge-generation-") &&
                            Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)).findFirst().orElseThrow();
                        obstruction[0] = Files.writeString(recovery.resolve("keep"), "recovery witness");
                    }
                }
            });
            throw new AssertionError("cleanup failure was hidden");
        }
        catch (IOException observed) {
            if (installed) {
                require(observed.getMessage().startsWith("generation installed but staging cleanup failed"),
                    "installed generation incorrectly reported as rolled back");
                require(observed.getCause() instanceof java.nio.file.DirectoryNotEmptyException,
                    "missing cleanup cause");
            }
            else {
                require(observed == primary, "cleanup replaced primary error");
                require(Arrays.stream(observed.getSuppressed()).anyMatch(java.nio.file.DirectoryNotEmptyException.class::isInstance),
                    "missing suppressed cleanup failure");
            }
        }
        if (installed) current(outputs); else previous(outputs, true);
        require(Files.readString(input).equals("original"), "cleanup changed original");
        require(Files.readString(obstruction[0]).equals("recovery witness"), "cleanup removed unrelated witness");
        cases++;
    }

    private static void observationChange(Path root) throws Exception {
        Path dir = Files.createDirectory(root.resolve("observation"));
        Path input = Files.writeString(dir.resolve("input"), "original");
        List<Path> outputs = outputs(dir);
        seed(outputs);
        AtomicInteger checks = new AtomicInteger();
        // First callback observes the path; the second runs after metadata was read,
        // immediately before FileDigests opens the same file. No timing race/thread.
        refuse(() -> CompanionArtifactPublisher.stageAndPublish(input, outputs,
            stages -> { throw new AssertionError("writer ran after inconsistent observation"); }, () -> {
                if (checks.incrementAndGet() == 2) Files.writeString(outputs.get(0), "concurrent larger user value");
            }));
        require(Files.readString(outputs.get(0)).equals("concurrent larger user value"), "concurrent value overwritten");
        require(Files.readString(outputs.get(1)).equals("old-1") && Files.readString(outputs.get(2)).equals("old-2"),
            "other generation members changed");
        require(Files.readString(input).equals("original"), "observation changed original");
        noStages(dir);
    }

    private static void symbolicOutputs(Path root) throws Exception {
        Path dir = Files.createDirectory(root.resolve("symbolic"));
        Path input = Files.writeString(dir.resolve("input"), "original");
        Path external = Files.writeString(dir.resolve("external"), "external bytes");
        List<Path> outputs = outputs(dir);
        Files.createSymbolicLink(outputs.get(0), external.getFileName());
        IOException primary = new IOException("cancel after replacing output link");
        try {
            CompanionArtifactPublisher.stageAndPublish(input, outputs, CompanionPublicationFailureSmoke::write,
                () -> { }, index -> { if (index == 0) throw primary; });
            throw new AssertionError("injected failure ignored");
        }
        catch (IOException observed) { require(observed == primary && observed.getSuppressed().length == 0, "link rollback failed"); }
        require(Files.isSymbolicLink(outputs.get(0)) && Files.readSymbolicLink(outputs.get(0)).equals(external.getFileName()),
            "original link identity lost");
        require(Files.readString(external).equals("external bytes"), "link referent modified");
        require(!Files.exists(outputs.get(1)) && !Files.exists(outputs.get(2)), "partial generation left");
        noStages(dir);
        cases++;
    }

    private static void cancellation(Path root, boolean existing) throws Exception {
        int visits = 0;
        for (int stop = 0; stop <= visits; stop++) {
            Path dir = Files.createDirectory(root.resolve("cancel-" + existing + "-" + stop));
            Path input = Files.writeString(dir.resolve("input"), "original");
            List<Path> outputs = outputs(dir);
            if (existing) seed(outputs);
            int selected = stop;
            AtomicInteger calls = new AtomicInteger();
            var cancellation = new CancellationException("checkpoint " + selected);
            try {
                CompanionArtifactPublisher.stageAndPublish(input, outputs.get(0), outputs.get(1), outputs.get(2),
                    (a, b, c) -> write(List.of(a, b, c)), () -> {
                        if (calls.incrementAndGet() == selected) throw cancellation;
                    });
                require(stop == 0, "cancellation ignored");
                visits = calls.get();
                current(outputs);
            }
            catch (CancellationException observed) {
                require(stop != 0 && observed == cancellation && observed.getSuppressed().length == 0, "cancellation rollback failed");
                previous(outputs, existing);
            }
            require(Files.readString(input).equals("original"), "cancellation changed original");
            noStages(dir);
            cases++;
        }
    }

    private static List<Path> outputs(Path dir) {
        return List.of(dir.resolve("image.dbg"), dir.resolve("image.dbg.c"), dir.resolve("image.dbg.gdb"));
    }

    private static void seed(List<Path> outputs) throws IOException {
        for (int index = 0; index < outputs.size(); index++) Files.writeString(outputs.get(index), "old-" + index);
    }

    private static void write(List<Path> outputs) throws IOException {
        for (int index = 0; index < outputs.size(); index++) Files.writeString(outputs.get(index), "new-" + index);
    }

    private static void current(List<Path> outputs) throws IOException {
        for (int index = 0; index < outputs.size(); index++) require(Files.readString(outputs.get(index)).equals("new-" + index), "new member missing");
    }

    private static void previous(List<Path> outputs, boolean existing) throws IOException {
        for (int index = 0; index < outputs.size(); index++) {
            if (existing) require(Files.readString(outputs.get(index)).equals("old-" + index), "previous bytes lost");
            else require(!Files.exists(outputs.get(index), LinkOption.NOFOLLOW_LINKS), "partial output remains");
        }
    }

    private static void noStages(Path dir) throws IOException {
        try (var paths = Files.list(dir)) {
            require(paths.noneMatch(path -> path.getFileName().toString().startsWith(".forge-")), "unexpected stage/recovery leak");
        }
    }

    @FunctionalInterface
    private interface Checked { void run() throws Exception; }

    private static void refuse(Checked action) throws Exception {
        try { action.run(); throw new AssertionError("invalid publication accepted"); }
        catch (IOException | IllegalArgumentException expected) {
            require(expected.getMessage() != null && !expected.getMessage().isBlank(), "missing diagnostic");
            cases++;
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
