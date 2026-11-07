package ghidradwarfforge.output;

import ghidradwarfforge.elf.SyntheticSourceSidecar;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileTime;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

/** Refusal and provenance controls on independent copies of a real export. */
public final class ArtifactValidationBindingSmoke {
    private static int checks;
    private static final AttachmentElfTransactionProbe.Host HOST = new AttachmentElfTransactionProbe.Host();

    public static void main(String[] args) throws Exception {
        if (args.length != 5) throw new IllegalArgumentException("report original sidecar source new-control-directory");
        Path root = Path.of(args[4]);
        Files.createDirectory(root);
        Path exported = Files.createDirectory(root.resolve("export"));
        Path retained = Files.createDirectory(root.resolve("retained"));
        Path original = Files.copy(Path.of(args[1]), root.resolve("original"));
        Path report = Files.copy(Path.of(args[0]), root.resolve("report.json"));
        Path sidecar = Files.copy(Path.of(args[2]), exported.resolve("artifact.dbg"));
        Path source = Files.copy(Path.of(args[3]), exported.resolve(Path.of(args[3]).getFileName()));
        Path retainedSource = Files.copy(source, retained.resolve(source.getFileName()));
        var sourceBundle = SourceBundleFiles.open(Path.of(args[3]), () -> false).orElse(null);
        if (sourceBundle != null) {
            for (Path dependency : sourceBundle.files().subList(1, sourceBundle.files().size())) {
                Files.copy(dependency, exported.resolve(dependency.getFileName()));
                Files.copy(dependency, retained.resolve(dependency.getFileName()));
            }
        }
        Path candidate = root.resolve("candidate.dbg");
        var plan = SyntheticSourceSidecar.prepare(sidecar, retained.toString(), () -> false);
        write(plan, candidate);
        var export = AttachmentExportBinding.observe(report, original, sidecar, source, HOST, () -> false);
        var derived = ArtifactValidationBinding.relocated(export, candidate, retainedSource, HOST, () -> false);
        if (sourceBundle != null) {
            // Copying an index alone must never authorize a relocated sidecar.
            for (Path dependency : sourceBundle.files().subList(1, sourceBundle.files().size())) {
                Path selected = retained.resolve(dependency.getFileName());
                Path hidden = selected.resolveSibling(selected.getFileName() + ".hidden");
                Files.move(selected, hidden);
                try {
                    reject(() -> ArtifactValidationBinding.relocated(export, candidate, retainedSource, HOST, () -> false));
                    reject(() -> derived.recheck(HOST, () -> false));
                }
                finally { Files.move(hidden, selected); }
            }
            derived.recheck(HOST, () -> false);
        }
        require(derived.derived() && !ArtifactValidationBinding.exported(export).derived(), "incorrect relationship");
        require(derived.claims().equals(export.claims()), "export claims were changed");
        require(derived.exportFiles().equals(export.files()), "reported export evidence was replaced");
        require(!derived.files().get("sidecar").digest().equals(export.files().get("sidecar").digest()), "derived hash not distinct");
        require(derived.files().get("source").digest().equals(export.files().get("source").digest()), "source bytes changed");
        Map<Path, FileDigests.Result> before = Map.of(original, FileDigests.read(original), report, FileDigests.read(report),
            sidecar, FileDigests.read(sidecar), source, FileDigests.read(source));
        reject(() -> AttachmentExportBinding.observe(report, original, candidate, retainedSource, HOST, () -> false));
        reject(() -> ArtifactValidationBinding.relocated(export, sidecar, retainedSource, HOST, () -> false));
        reject(() -> ArtifactValidationBinding.relocated(export, candidate, source, HOST, () -> false));
        Path wrongName = Files.copy(retainedSource, retained.resolve("wrong-name.c"));
        reject(() -> ArtifactValidationBinding.relocated(export, candidate, wrongName, HOST, () -> false));
        Path wrongDirectory = Files.createDirectory(root.resolve("different-source"));
        Path wrongCandidate = root.resolve("other-directory.dbg");
        write(SyntheticSourceSidecar.prepare(sidecar, wrongDirectory.toString(), () -> false), wrongCandidate);
        reject(() -> ArtifactValidationBinding.relocated(export, wrongCandidate, retainedSource, HOST, () -> false));
        for (Path selected : new Path[] {candidate, retainedSource}) {
            byte[] bytes = Files.readAllBytes(selected);
            FileTime modified = Files.getLastModifiedTime(selected);
            byte[] bad = bytes.clone(); bad[bad.length - 1] ^= 1;
            Files.write(selected, bad); Files.setLastModifiedTime(selected, modified);
            reject(() -> derived.recheck(HOST, () -> false));
            reject(() -> ArtifactValidationBinding.relocated(export, candidate, retainedSource, HOST, () -> false));
            Files.write(selected, bytes); Files.setLastModifiedTime(selected, modified);
        }
        Path alias = root.resolve("hardlink");
        Files.createLink(alias, candidate);
        reject(() -> ArtifactValidationBinding.relocated(export, alias, retainedSource, HOST, () -> false));
        Files.delete(alias);
        Path symbolic = root.resolve("symlink");
        Files.createSymbolicLink(symbolic, candidate);
        reject(() -> ArtifactValidationBinding.relocated(export, symbolic, retainedSource, HOST, () -> false));
        Files.delete(symbolic);
        AtomicInteger visits = new AtomicInteger();
        ArtifactValidationBinding.relocated(export, candidate, retainedSource, HOST,
            () -> { visits.incrementAndGet(); return false; });
        int[] stops = {1, 2, 10, 50, visits.get() / 2, visits.get() - 1, visits.get()};
        for (int stop : stops) {
            AtomicInteger current = new AtomicInteger();
            try {
                ArtifactValidationBinding.relocated(export, candidate, retainedSource, HOST,
                    () -> current.incrementAndGet() == stop);
                throw new AssertionError("missed binding cancellation " + stop);
            }
            catch (CancellationException expected) { }
        }
        for (var entry : before.entrySet()) require(FileDigests.read(entry.getKey()).equals(entry.getValue()), "reported input changed");
        require(Arrays.equals(Files.readAllBytes(source), Files.readAllBytes(retainedSource)), "retained source changed");
        System.out.printf("derived-binding-smoke=PASS refusals=%d sampledCancellation=%d observedBoundaries=%d%n", checks, stops.length, visits.get());
    }

    private static void write(SyntheticSourceSidecar.Plan plan, Path output) throws Exception {
        try (var stage = FileChannel.open(output, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            plan.writeStage(stage, () -> false);
        }
        plan.requireMatches(output, () -> false);
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    @FunctionalInterface private interface Checked { void run() throws Exception; }
    private static void reject(Checked operation) throws Exception {
        try { operation.run(); throw new AssertionError("expected derived binding refusal"); }
        catch (IOException expected) { checks++; }
    }
}
