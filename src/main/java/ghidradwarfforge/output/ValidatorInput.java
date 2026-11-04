package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/**
 * Read-only tool/configuration provenance. These files are never backed up or
 * replaced by attachment, so multiple hard links are permitted. Identity,
 * change indicators and complete content are rechecked; this is not a complete
 * metadata-preservation snapshot and cannot be used as recovery material.
 * All-role alias checks remain the caller's responsibility.
 */
public final class ValidatorInput {
    public record Observation(String identity, long links, long bytes, String changeIndicators) {
        public Observation {
            Objects.requireNonNull(identity);
            Objects.requireNonNull(changeIndicators);
            if (identity.isEmpty() || links < 1 || bytes < 0) {
                throw new IllegalArgumentException("invalid validator file observation");
            }
        }
    }

    public record Snapshot(Path path, FileDigests.Result digest, Observation observation) {
        public Snapshot {
            Objects.requireNonNull(path);
            Objects.requireNonNull(digest);
            Objects.requireNonNull(observation);
        }
    }

    private ValidatorInput() { }

    public static Snapshot observe(Path selected, BooleanSupplier cancelled) throws IOException {
        check(cancelled);
        Path path = FileSystemPaths.resolveLeaf(selected, "validator input");
        try {
            var before = facts(path, cancelled);
            var digest = FileDigests.read(path, cancelled,
                file -> Files.newInputStream(file, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS));
            var after = facts(path, cancelled);
            if (!before.equals(after) || digest.byteCount() != after.bytes()) {
                throw new IOException("validator input changed during observation");
            }
            check(cancelled);
            return new Snapshot(path, digest, after);
        }
        catch (IOException failure) {
            throw new IOException("cannot observe validator input " + path + ": " + failure.getMessage(), failure);
        }
    }

    public static void unchanged(Snapshot expected, BooleanSupplier cancelled) throws IOException {
        if (!expected.equals(observe(expected.path(), cancelled))) {
            throw new IOException("validator input changed: " + expected.path());
        }
    }

    private static Observation facts(Path path, BooleanSupplier cancelled) throws IOException {
        check(cancelled);
        if (com.sun.jna.Platform.isWindows()) {
            // Reuse the audited volume/file-ID reader. Java's Windows fileKey
            // may be null; never substitute a pathname for file identity.
            var value = new WindowsFileMetadata().inspectFacts(path, cancelled);
            return new Observation(value.identity(), value.links(), value.bytes(),
                value.attributes() + ":" + value.created() + ":" + value.modified() + ":" + value.changed());
        }
        if (!com.sun.jna.Platform.isLinux()) throw new IOException("unsupported validator input host");
        var value = Files.readAttributes(path, "unix:dev,ino,nlink,size,mode,uid,gid,ctime,lastModifiedTime",
            LinkOption.NOFOLLOW_LINKS);
        int mode = ((Number) value.get("mode")).intValue();
        if ((mode & 0170000) != 0100000) throw new IOException("validator input must be a regular non-link file");
        return new Observation(value.get("dev") + ":" + value.get("ino"),
            ((Number) value.get("nlink")).longValue(), ((Number) value.get("size")).longValue(),
            mode + ":" + value.get("uid") + ":" + value.get("gid") + ":" + value.get("ctime") + ":" + value.get("lastModifiedTime"));
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("validator input observation cancelled");
    }
}
