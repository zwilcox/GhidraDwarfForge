package ghidradwarfforge.output;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/**
 * Compares a current export report's SHA-256 claims with three explicitly selected
 * files. Reported paths remain opaque; only the four supplied paths are accessed,
 * using their actual host traversal without rewriting their spelling. Equal
 * hashes are agreement with an unauthenticated claim, not file identity, ELF or
 * source validation, a snapshot, or readiness to attach a debuglink. Ordinary
 * export does not call this helper.
 *
 * The report is completely parsed before any artifact is inspected. All three
 * artifacts must currently resolve to regular files before digesting begins.
 * Selected leaf links are followed for this read-only observation. A regular-file
 * precheck rejects known special files; it cannot prevent concurrent replacement.
 * Observations occur sequentially, not as an immutable cross-file snapshot.
 *
 * ExportReportClaims' bounded parsing and FileDigests' 64 KiB streaming buffer
 * apply. No inventories or whole artifacts are retained. Cancellation is checked
 * around each step and inside the reused readers, including before returning;
 * it cannot interrupt an operating-system call already blocked. Every opened
 * stream is owned and closed by the reused reader. Failure returns no Result.
 */
public final class ExportArtifactHashBinding {
    public enum Agreement {
        MATCHING_REPORTED_SHA256, DIFFERENT_REPORTED_SHA256
    }

    /** selectedPath is the caller's spelling, not a canonical path or identity. */
    public record Artifact(Path selectedPath, FileDigests.Result observed,
            Agreement agreement) {
        public Artifact {
            Objects.requireNonNull(selectedPath, "selectedPath");
            Objects.requireNonNull(observed, "observed");
            Objects.requireNonNull(agreement, "agreement");
        }
    }

    /** Reported PARTIAL and NOT_RUN retain their meanings; there is no total approval. */
    public record Result(ExportReportClaims claims, Artifact original,
            Artifact sidecar, Artifact source) {
        public Result {
            Objects.requireNonNull(claims, "claims");
            requireAgreement(original, claims.artifacts().inputSha256());
            requireAgreement(sidecar, claims.artifacts().outputSha256());
            requireAgreement(source, claims.artifacts().sourceSha256());
        }
    }

    /** Test seam: opened streams transfer to the report/digest reader for closure. */
    interface FileAccess {
        BasicFileAttributes attributes(Path path) throws IOException;
        InputStream open(Path path) throws IOException;
    }

    private static final FileAccess FILES = new FileAccess() {
        @Override
        public BasicFileAttributes attributes(Path path) throws IOException {
            return Files.readAttributes(path, BasicFileAttributes.class);
        }

        @Override
        public InputStream open(Path path) throws IOException {
            return Files.newInputStream(path);
        }
    };

    private ExportArtifactHashBinding() {
    }

    public static Result observe(Path report, Path original, Path sidecar, Path source)
            throws IOException {
        return observe(report, original, sidecar, source, () -> false);
    }

    public static Result observe(Path report, Path original, Path sidecar, Path source,
            BooleanSupplier cancelled) throws IOException {
        return observe(report, original, sidecar, source, cancelled, FILES);
    }

    static Result observe(Path report, Path original, Path sidecar, Path source,
            BooleanSupplier cancelled, FileAccess access) throws IOException {
        Objects.requireNonNull(report, "report");
        Objects.requireNonNull(original, "original");
        Objects.requireNonNull(sidecar, "sidecar");
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(cancelled, "cancelled");
        Objects.requireNonNull(access, "access");
        requireRegular(report, "report", cancelled, access);
        ExportReportClaims claims = ExportReportClaims.read(report, cancelled,
            access::open, ReportJsonReader.DEFAULT_LIMITS);
        requireRegular(original, "original", cancelled, access);
        requireRegular(sidecar, "sidecar", cancelled, access);
        requireRegular(source, "source", cancelled, access);
        Artifact input = digest(original, claims.artifacts().inputSha256(), cancelled, access);
        Artifact output = digest(sidecar, claims.artifacts().outputSha256(), cancelled, access);
        Artifact text = digest(source, claims.artifacts().sourceSha256(), cancelled, access);
        checkCancelled(cancelled);
        return new Result(claims, input, output, text);
    }

    private static void requireRegular(Path path, String role, BooleanSupplier cancelled,
            FileAccess access) throws IOException {
        checkCancelled(cancelled);
        BasicFileAttributes attributes = access.attributes(path);
        if (!attributes.isRegularFile()) {
            throw new IOException("selected " + role + " is not a regular file: " + path);
        }
        checkCancelled(cancelled);
    }

    private static Artifact digest(Path path, String reportedSha256,
            BooleanSupplier cancelled, FileAccess access) throws IOException {
        FileDigests.Result observed = FileDigests.read(path, cancelled, access::open);
        return new Artifact(path, observed, agreement(reportedSha256, observed));
    }

    private static Agreement agreement(String reportedSha256, FileDigests.Result observed) {
        return reportedSha256.equalsIgnoreCase(observed.sha256())
            ? Agreement.MATCHING_REPORTED_SHA256 : Agreement.DIFFERENT_REPORTED_SHA256;
    }

    private static void requireAgreement(Artifact artifact, String reportedSha256) {
        Objects.requireNonNull(artifact, "artifact");
        if (artifact.agreement() != agreement(reportedSha256, artifact.observed())) {
            throw new IllegalArgumentException("artifact agreement contradicts reported SHA-256");
        }
    }

    private static void checkCancelled(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) {
            throw new CancellationException("export artifact hash binding cancelled");
        }
    }
}
