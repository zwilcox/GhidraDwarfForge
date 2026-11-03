package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/** Recoverable publication of a complete sidecar/source/companion generation. */
public final class CompanionArtifactPublisher {
    @FunctionalInterface
    public interface StagedWriter {
        void write(Path sidecar, Path source, Path companion) throws Exception;
    }

    @FunctionalInterface
    interface InstallHook {
        void afterInstall(int index) throws Exception;
    }

    private record State(Object key, long size, FileTime modified, String sha256, Path link) {
    }

    private static final class CheckFailure extends RuntimeException {
        private final Exception failure;

        CheckFailure(Exception failure) {
            super(failure);
            this.failure = failure;
        }
    }

    private CompanionArtifactPublisher() {
    }

    /** Preflight all destinations before staging, without following output leaves for replacement. */
    public static void validate(Path input, Path sidecar, Path source, Path companion,
            Path... additionalInputs) throws IOException {
        List<Path> targets = resolve(input, sidecar, source, companion);
        for (Path additional : additionalInputs) {
            Path protectedPath = FileSystemPaths.resolveLeaf(additional, "protected input");
            for (Path target : targets) {
                if (FileSystemPaths.aliases(target, protectedPath)) {
                    throw new IOException("generation destination aliases a protected input: " + protectedPath);
                }
            }
        }
    }

    public static void stageAndPublish(Path input, Path sidecar, Path source, Path companion,
            StagedWriter writer, ArtifactPairPublisher.PrePublishCheck check) throws Exception {
        stageAndPublish(input, sidecar, source, companion, writer, check, index -> { });
    }

    static void stageAndPublish(Path input, Path sidecar, Path source, Path companion,
            StagedWriter writer, ArtifactPairPublisher.PrePublishCheck check, InstallHook hook)
            throws Exception {
        Objects.requireNonNull(writer, "writer");
        Objects.requireNonNull(check, "check");
        Objects.requireNonNull(hook, "hook");
        List<Path> targets = resolve(input, sidecar, source, companion);
        List<State> previous = new ArrayList<>();
        for (Path target : targets) {
            previous.add(observe(target, check));
        }
        check.check();
        Path directory = Files.createTempDirectory(targets.get(0).getParent(), ".forge-generation-");
        Path[] stages = new Path[3];
        Path[] backups = new Path[3];
        State[] installed = new State[3];
        boolean[] replaced = new boolean[3];
        boolean retainRecovery = false;
        Exception failure = null;
        try {
            for (int index = 0; index < stages.length; index++) {
                // The existing line-table writer derives its source directory
                // from the stage parent. Keep stages beside the final files.
                stages[index] = Files.createTempFile(directory.getParent(),
                    directory.getFileName() + "-stage-" + index + "-", ".staged");
            }
            writer.write(stages[0], stages[1], stages[2]);
            for (Path stage : stages) {
                if (!Files.isRegularFile(stage, LinkOption.NOFOLLOW_LINKS)) {
                    throw new IOException("generation writer did not produce a regular staged file");
                }
            }
            // GDB's source freshness check must not warn merely because source
            // generation finished after native sidecar generation.
            FileTime sourceTime = Files.getLastModifiedTime(stages[1]);
            if (Files.getLastModifiedTime(stages[0]).compareTo(sourceTime) < 0) {
                Files.setLastModifiedTime(stages[0], sourceTime);
            }
            check.check();
            for (int index = 0; index < targets.size(); index++) {
                requireUnchanged(targets.get(index), previous.get(index), check);
            }
            for (int index = 0; index < targets.size(); index++) {
                check.check();
                Path target = targets.get(index);
                State next = observe(stages[index], check);
                requireUnchanged(target, previous.get(index), check);
                if (previous.get(index) != null) {
                    Path backup = directory.resolve("backup-" + index);
                    move(target, backup);
                    backups[index] = backup;
                }
                move(stages[index], target);
                replaced[index] = true;
                installed[index] = next;
                hook.afterInstall(index);
            }
            check.check();
        }
        catch (Exception problem) {
            failure = problem;
            for (int index = targets.size() - 1; index >= 0; index--) {
                if (!replaced[index] && backups[index] == null) {
                    continue;
                }
                try {
                    // Do not roll an unrelated concurrent user's change back.
                    // An unobserved install is uncertain, so retain recovery.
                    if (replaced[index] && installed[index] == null) {
                        throw new IOException("installed output could not be observed: " + targets.get(index));
                    }
                    requireUnchanged(targets.get(index), installed[index]);
                    if (backups[index] != null) {
                        move(backups[index], targets.get(index));
                    }
                    else if (replaced[index]) {
                        Files.delete(targets.get(index));
                    }
                }
                catch (Exception rollbackFailure) {
                    retainRecovery = true;
                    problem.addSuppressed(rollbackFailure);
                }
            }
            if (retainRecovery) {
                problem.addSuppressed(new IOException("generation recovery files retained at " + directory +
                    "; uninstalled stages: " + java.util.Arrays.toString(stages)));
            }
            throw problem;
        }
        finally {
            if (!retainRecovery) {
                try {
                    for (Path stage : stages) {
                        if (stage != null) {
                            Files.deleteIfExists(stage);
                        }
                    }
                    for (Path backup : backups) {
                        if (backup != null) {
                            Files.deleteIfExists(backup);
                        }
                    }
                    Files.delete(directory);
                }
                catch (IOException cleanupFailure) {
                    if (failure != null) {
                        failure.addSuppressed(cleanupFailure);
                    }
                    else {
                        throw new IOException("generation installed but staging cleanup failed: " + directory,
                            cleanupFailure);
                    }
                }
            }
        }
    }

    private static List<Path> resolve(Path input, Path sidecar, Path source, Path companion)
            throws IOException {
        Path original = FileSystemPaths.resolveLeaf(input, "original ELF");
        if (!Files.isRegularFile(original) || !Files.isReadable(original)) {
            throw new IOException("original ELF is not a readable regular file: " + original);
        }
        List<Path> targets = List.of(FileSystemPaths.resolveLeaf(sidecar, "sidecar"),
            FileSystemPaths.resolveLeaf(source, "source"),
            FileSystemPaths.resolveLeaf(companion, "GDB companion"));
        List<Path> all = new ArrayList<>(targets);
        all.add(original);
        for (int first = 0; first < all.size(); first++) {
            for (int second = first + 1; second < all.size(); second++) {
                if (FileSystemPaths.aliases(all.get(first), all.get(second))) {
                    throw new IOException("generation paths alias one another: " + all.get(first) + " and " + all.get(second));
                }
            }
        }
        Path parent = targets.get(0).getParent();
        for (Path target : targets) {
            if (!parent.equals(target.getParent())) {
                throw new IOException("sidecar, source and GDB companion must share an output directory");
            }
            try {
                var attributes = Files.readAttributes(target, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                if (!attributes.isRegularFile() && !attributes.isSymbolicLink()) {
                    throw new IOException("generation destination is not a regular file or symbolic link: " + target);
                }
            }
            catch (NoSuchFileException missing) {
                // A new destination is permitted after complete alias preflight.
            }
        }
        return targets;
    }

    private static State observe(Path path) throws IOException {
        try {
            return observe(path, () -> { });
        }
        catch (IOException failure) {
            throw failure;
        }
        catch (Exception failure) {
            throw new IOException(failure);
        }
    }

    private static State observe(Path path, ArtifactPairPublisher.PrePublishCheck check) throws Exception {
        check.check();
        BasicFileAttributes attributes;
        try {
            attributes = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        }
        catch (NoSuchFileException missing) {
            return null;
        }
        if (!attributes.isRegularFile() && !attributes.isSymbolicLink()) {
            throw new IOException("generation destination is not a regular file or symbolic link: " + path);
        }
        String hash = null;
        if (attributes.isRegularFile()) {
            try {
                hash = FileDigests.read(path, () -> {
                    try {
                        check.check();
                        return false;
                    }
                    catch (Exception failure) {
                        throw new CheckFailure(failure);
                    }
                }).sha256();
            }
            catch (CheckFailure failure) {
                throw failure.failure;
            }
        }
        Path link = attributes.isSymbolicLink() ? Files.readSymbolicLink(path) : null;
        BasicFileAttributes after = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!Objects.equals(attributes.fileKey(), after.fileKey()) || attributes.size() != after.size() ||
                !attributes.lastModifiedTime().equals(after.lastModifiedTime())) {
            throw new IOException("generation destination changed while observing it: " + path);
        }
        return new State(attributes.fileKey(), attributes.size(), attributes.lastModifiedTime(), hash, link);
    }

    private static void requireUnchanged(Path path, State expected) throws IOException {
        if (!Objects.equals(expected, observe(path))) {
            throw new IOException("generation destination changed concurrently: " + path);
        }
    }

    private static void requireUnchanged(Path path, State expected,
            ArtifactPairPublisher.PrePublishCheck check) throws Exception {
        if (!Objects.equals(expected, observe(path, check))) {
            throw new IOException("generation destination changed concurrently: " + path);
        }
    }

    private static void move(Path source, Path target) throws IOException {
        try {
            Files.move(source, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        }
        catch (AtomicMoveNotSupportedException unsupported) {
            throw new IOException("output filesystem does not support atomic generation replacement", unsupported);
        }
    }
}
