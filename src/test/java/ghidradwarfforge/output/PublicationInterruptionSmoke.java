package ghidradwarfforge.output;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

/** Pause a cooperating writer between public renames, including an abrupt process death. */
public final class PublicationInterruptionSmoke {
    private static final List<String> NAMES = List.of("image.dbg", "image.dbg.c", "image.dbg.gdb.py");

    public static void main(String[] args) throws Exception {
        Path root = Path.of(args[0]);
        CompanionArtifactPublisher.stageAndPublish(root.resolve("input"),
            NAMES.stream().map(root::resolve).toList(), stages -> {
                for (int i = 0; i < stages.size(); i++) Files.writeString(stages.get(i), "new " + NAMES.get(i));
            }, () -> { }, index -> {
                if (index == 0) {
                    Files.createFile(root.resolve("ready"));
                    await(root.resolve("continue"));
                }
            });
    }

    static void exercise(Path root) throws Exception {
        legacyClaim(root.resolve("legacy-claim"));
        interruptedByError(root.resolve("error-before-install"), false);
        interruptedByError(root.resolve("error-after-install"), true);
        for (boolean kill : List.of(false, true)) {
            Path fixtures = Files.createDirectory(root.resolve(kill ? "interrupted" : "overlap"));
            Files.writeString(fixtures.resolve("input"), "original");
            for (String name : NAMES) Files.writeString(fixtures.resolve(name), "old " + name);
            String cp = classes(PublicationInterruptionSmoke.class) + File.pathSeparator +
                classes(CompanionArtifactPublisher.class) + File.pathSeparator + classes(FileDigests.class);
            Process child = new ProcessBuilder(ProcessHandle.current().info().command().orElseThrow(),
                "-cp", cp, PublicationInterruptionSmoke.class.getName(), fixtures.toString())
                .redirectErrorStream(true).redirectOutput(fixtures.resolve("child.log").toFile()).start();
            try {
                await(fixtures.resolve("ready"));
                Path owner = PublicationJournal.claimPath(fixtures.resolve(NAMES.get(0)));
                Path inventory = Path.of(properties(owner).getProperty("inventory"));
                Properties record = properties(inventory);
                require(record.getProperty("count").equals("3"), "incomplete generation inventory");
                for (int i = 0; i < NAMES.size(); i++) {
                    String prefix = "file." + i;
                    Path target = Path.of(record.getProperty(prefix + ".target"));
                    Path backup = Path.of(record.getProperty(prefix + ".backup"));
                    Path stage = Path.of(record.getProperty(prefix + ".stage"));
                    Path expectedTarget = fixtures.resolve(NAMES.get(i));
                    require(target.getFileName().equals(expectedTarget.getFileName()) &&
                        Files.isSameFile(target.getParent(), fixtures) && Files.isSameFile(target, expectedTarget),
                        "wrong recovery target: " + target + ", expected " + expectedTarget);
                    Path oldFile = i == 0 ? backup : target;
                    Path newFile = i == 0 ? target : stage;
                    require(Files.readString(oldFile).equals("old " + NAMES.get(i)) &&
                        FileDigests.read(oldFile).sha256().equals(record.getProperty(prefix + ".old.sha256")),
                        "old generation cannot be recovered from inventory");
                    require(Files.readString(newFile).equals("new " + NAMES.get(i)) &&
                        FileDigests.read(newFile).sha256().equals(record.getProperty(prefix + ".new.sha256")),
                        "new generation cannot be identified");
                }
                refuseCompetingPair(fixtures);
                ArtifactPairPublisher.stageAndPublish(fixtures.resolve("unrelated.dbg"), fixtures.resolve("unrelated.c"),
                    p -> Files.writeString(p, "independent sidecar"), p -> Files.writeString(p, "independent source"),
                    () -> { });
                require(Files.readString(fixtures.resolve("unrelated.c")).equals("independent source"),
                    "unrelated generation in the same directory could not publish");
                if (kill) {
                    child.destroyForcibly();
                    require(child.waitFor(15, TimeUnit.SECONDS), "interrupted child did not terminate");
                    refuseCompetingPair(fixtures);
                    require(properties(inventory).equals(record), "successor changed the interrupted inventory");
                    require(!Files.exists(inventory.resolveSibling("committed")), "partial installation marked committed");
                }
                else {
                    Files.createFile(fixtures.resolve("continue"));
                    require(child.waitFor(15, TimeUnit.SECONDS) && child.exitValue() == 0, "ordinary export failed");
                    for (String name : NAMES) require(Files.readString(fixtures.resolve(name)).equals("new " + name),
                        "overlap returned a mixed generation");
                    require(!Files.exists(owner) && !Files.exists(inventory), "successful export leaked its claim");
                }
                require(Files.readString(fixtures.resolve("input")).equals("original"), "publication changed input");
            }
            finally {
                if (child.isAlive()) {
                    child.destroyForcibly();
                    require(child.waitFor(15, TimeUnit.SECONDS), "test child could not be stopped");
                }
            }
        }
        System.out.println("generation-overlap-and-process-interruption=PASS");
    }

    private static void legacyClaim(Path root) throws Exception {
        Files.createDirectory(root);
        Path target = root.toRealPath().resolve(NAMES.getFirst());
        Path claim = Files.createDirectory(PublicationJournal.claimPath(target));
        Path inventory = Files.createDirectory(target.resolveSibling(".forge-generation-legacy"))
            .resolve(PublicationJournal.INVENTORY);
        Properties legacy = new Properties();
        legacy.setProperty("file.0.claim", claim.toString());
        try (var out = Files.newOutputStream(inventory)) { legacy.store(out, null); }
        try {
            ArtifactPairPublisher.stageAndPublish(target, target.resolveSibling(NAMES.get(1)),
                p -> Files.writeString(p, "sidecar"), p -> Files.writeString(p, "source"), () -> { });
            throw new AssertionError("export ignored an interrupted legacy claim");
        }
        catch (IOException expected) {
            require(expected.getMessage().contains(inventory.toString()), "missing legacy inventory: " + expected);
            require(!expected.getMessage().contains("owner.properties"), "suggested an absent owner file");
        }
        require(properties(inventory).equals(legacy) && Files.isDirectory(claim) && !Files.exists(target),
            "legacy recovery or output was modified by a retry");
    }

    private static void interruptedByError(Path root, boolean afterInstall) throws Exception {
        Files.createDirectory(root);
        Path original = Files.writeString(root.resolve("input"), "original");
        List<Path> targets = NAMES.stream().map(root::resolve).toList();
        for (Path target : targets) Files.writeString(target, "old " + target.getFileName());
        Path claim = PublicationJournal.claimPath(targets.getFirst());
        AssertionError failure = new AssertionError("simulated fatal installation error");
        try {
            CompanionArtifactPublisher.stageAndPublish(original, targets, stages -> {
                for (int i = 0; i < stages.size(); i++) Files.writeString(stages.get(i), "new " + NAMES.get(i));
            }, () -> {
                if (!afterInstall && Files.exists(claim)) throw failure;
            }, () -> { }, index -> { if (index == 0 && afterInstall) throw failure; });
            throw new AssertionError("publication swallowed the installation error");
        }
        catch (AssertionError observed) { if (observed != failure) throw observed; }
        Path inventory = Path.of(properties(claim).getProperty("inventory"));
        Properties record = properties(inventory);
        require(!Files.exists(inventory.resolveSibling("committed")), "incomplete publication marked committed");
        refuseCompetingPair(root);
        for (int i = 0; i < targets.size(); i++) {
            boolean installed = i == 0 && afterInstall;
            String prefix = "file." + i;
            Path old = installed ? Path.of(record.getProperty(prefix + ".backup")) : targets.get(i);
            Path next = installed ? targets.get(i) : Path.of(record.getProperty(prefix + ".stage"));
            require(Files.readString(old).equals("old " + NAMES.get(i)) &&
                Files.readString(next).equals("new " + NAMES.get(i)), "fatal error discarded a generation");
        }
        require(Files.readString(original).equals("original"), "fatal error changed the original");
    }

    private static void refuseCompetingPair(Path root) throws Exception {
        root = root.toRealPath();
        try {
            ArtifactPairPublisher.stageAndPublish(root.resolve(NAMES.get(0)), root.resolve(NAMES.get(1)),
                path -> Files.writeString(path, "competitor sidecar"), path -> Files.writeString(path, "competitor source"),
                () -> { });
            throw new AssertionError("competing writer replaced a claimed generation");
        }
        catch (IOException expected) {
            require(expected.getMessage().contains(PublicationJournal.claimPath(root.resolve(NAMES.get(0))).toString()) ||
                expected.getMessage().contains(PublicationJournal.claimPath(root.resolve(NAMES.get(1))).toString()),
                "missing recovery location: " + expected);
        }
    }

    private static Path classes(Class<?> type) throws Exception {
        return Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI());
    }

    private static Properties properties(Path file) throws IOException {
        Properties result = new Properties();
        try (var input = Files.newInputStream(file)) { result.load(input); }
        return result;
    }

    private static void await(Path file) throws Exception {
        long started = System.nanoTime();
        while (!Files.exists(file)) {
            if (System.nanoTime() - started > TimeUnit.SECONDS.toNanos(30)) throw new IOException("timed out waiting for " + file);
            Thread.sleep(20);
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
