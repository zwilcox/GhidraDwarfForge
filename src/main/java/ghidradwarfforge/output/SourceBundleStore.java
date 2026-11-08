package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.BooleanSupplier;

/**
 * Installs complete content-addressed source files before the mutable sidecar/index pair.
 * Installed files are retained even on failure: another export may already reference them.
 * This store never replaces or removes an existing destination, including a conflicting one.
 */
public final class SourceBundleStore {
    record State(Object key, long size, FileTime modified, String sha256) { }
    private record Entry(Path path, State state) { }

    @FunctionalInterface
    interface InstallHook {
        void afterInstall(int index, Path target) throws IOException;

        default void beforeLink(Path target) throws IOException { }
    }

    public static final class Installed {
        private final List<Entry> entries;
        private final List<Path> protectedPaths;

        private Installed(List<Entry> entries, List<Path> protectedPaths) {
            this.entries = List.copyOf(entries);
            this.protectedPaths = List.copyOf(protectedPaths);
        }

        /** Recheck immediately before publishing any sidecar that refers to this source set. */
        public void verify(BooleanSupplier cancelled) throws IOException {
            for (Entry entry : entries) {
                SourceBundle.check(cancelled);
                rejectAliases(entry.path(), protectedPaths);
                State current = observe(entry.path(), entry.state().size(), entry.state().sha256(), cancelled);
                if (!entry.state().equals(current)) {
                    throw new IOException("source generation changed before sidecar publication: " + entry.path());
                }
            }
        }

        /** Reused source files can have later mtimes than a newly staged sidecar. */
        public void synchronizeSidecarTime(Path stagedSidecar, BooleanSupplier cancelled) throws IOException {
            verify(cancelled);
            FileTime latest = Files.getLastModifiedTime(stagedSidecar, LinkOption.NOFOLLOW_LINKS);
            for (Entry entry : entries) {
                if (entry.state().modified().compareTo(latest) > 0) latest = entry.state().modified();
            }
            Files.setLastModifiedTime(stagedSidecar, latest);
        }

        public List<Path> files() { return entries.stream().map(Entry::path).toList(); }
    }

    private SourceBundleStore() { }

    /**
     * The protected paths include the original input, sidecar and any mutable companions/logs.
     * The primary index is always protected. Existing hard-link or symbolic-link aliases fail.
     */
    public static Installed install(Path index, SourceBundle.Plan plan, List<Path> protectedPaths,
            BooleanSupplier cancelled) throws IOException {
        return install(index, plan, protectedPaths, cancelled, (number, target) -> { });
    }

    static Installed install(Path index, SourceBundle.Plan plan, List<Path> protectedPaths,
            BooleanSupplier cancelled, InstallHook hook) throws IOException {
        Objects.requireNonNull(plan, "plan");
        Objects.requireNonNull(hook, "hook");
        SourceBundle.check(cancelled);
        Path resolvedIndex = FileSystemPaths.resolveLeaf(index, "source index");
        if (!resolvedIndex.getFileName().toString().equals(plan.manifest().indexName())) {
            throw new IOException("source manifest names a different index");
        }
        Path directory = resolvedIndex.getParent();
        var protectedResolved = new ArrayList<Path>();
        protectedResolved.add(resolvedIndex);
        for (Path path : protectedPaths) {
            protectedResolved.add(FileSystemPaths.resolveLeaf(path, "protected source generation input/output"));
        }
        List<String> names = plan.fileNames();
        // Preflight every destination, so a known conflict cannot cause even unreferenced writes.
        for (String name : names) {
            SourceBundle.check(cancelled);
            Path target = directory.resolve(name);
            rejectAliases(target, protectedResolved);
            observe(target, plan.expectedBytes(name), plan.expectedSha256(name), cancelled);
        }
        var entries = new ArrayList<Entry>();
        for (String name : names) {
            SourceBundle.check(cancelled);
            // The manifest is last in Plan.fileNames(). Recheck all referenced files first.
            if (name.equals(plan.manifestName())) new Installed(entries, protectedResolved).verify(cancelled);
            Path target = directory.resolve(name);
            rejectAliases(target, protectedResolved);
            State state = observe(target, plan.expectedBytes(name), plan.expectedSha256(name), cancelled);
            if (state == null) {
                Path stage = Files.createTempFile(directory, ".forge-source-part-", ".staged");
                try {
                    write(stage, plan.bytes(name), cancelled);
                    observe(stage, plan.expectedBytes(name), plan.expectedSha256(name), cancelled);
                    SourceBundle.check(cancelled);
                    rejectAliases(target, protectedResolved);
                    hook.beforeLink(target);
                    try {
                        // createLink is exclusive. Atomic rename can overwrite a competing creator
                        // on some providers even when REPLACE_EXISTING was not requested.
                        Files.createLink(target, stage);
                    }
                    catch (FileAlreadyExistsException concurrent) {
                        // Accept only a complete identical regular file from another publisher.
                    }
                    catch (UnsupportedOperationException unsupported) {
                        throw new IOException("multi-file source installation requires hard-link support", unsupported);
                    }
                    state = observe(target, plan.expectedBytes(name), plan.expectedSha256(name), cancelled);
                    if (state == null) throw new IOException("installed source disappeared: " + target);
                }
                finally {
                    Files.deleteIfExists(stage);
                }
            }
            entries.add(new Entry(target, state));
            hook.afterInstall(entries.size() - 1, target);
        }
        var installed = new Installed(entries, protectedResolved);
        installed.verify(cancelled);
        return installed;
    }

    private static void write(Path stage, byte[] bytes, BooleanSupplier cancelled) throws IOException {
        try (var channel = FileChannel.open(stage, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)) {
            for (int offset = 0; offset < bytes.length;) {
                SourceBundle.check(cancelled);
                ByteBuffer buffer = ByteBuffer.wrap(bytes, offset, Math.min(65536, bytes.length - offset));
                while (buffer.hasRemaining()) {
                    SourceBundle.check(cancelled);
                    if (channel.write(buffer) <= 0) throw new IOException("source staging write made no progress");
                }
                offset = buffer.position();
            }
            channel.force(true);
        }
    }

    private static void rejectAliases(Path target, List<Path> protectedPaths) throws IOException {
        for (Path protectedPath : protectedPaths) {
            if (FileSystemPaths.aliases(target, protectedPath)) {
                throw new IOException("source generation destination aliases a protected file: " + protectedPath);
            }
        }
    }

    static State observe(Path path, long bytes, String sha256, BooleanSupplier cancelled) throws IOException {
        SourceBundle.check(cancelled);
        BasicFileAttributes before;
        try { before = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS); }
        catch (NoSuchFileException absent) { return null; }
        if (!before.isRegularFile() || before.size() != bytes) {
            throw new IOException("source generation path is not an identical regular file: " + path);
        }
        FileDigests.Result digest = FileDigests.read(path, cancelled,
            file -> Files.newInputStream(file, LinkOption.NOFOLLOW_LINKS));
        var after = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!after.isRegularFile() || !Objects.equals(before.fileKey(), after.fileKey()) ||
                before.size() != after.size() || !before.lastModifiedTime().equals(after.lastModifiedTime()) ||
                digest.byteCount() != bytes || !digest.sha256().equals(sha256)) {
            throw new IOException("source generation has conflicting or changing content: " + path);
        }
        return new State(after.fileKey(), after.size(), after.lastModifiedTime(), digest.sha256());
    }
}
