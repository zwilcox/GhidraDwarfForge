package ghidradwarfforge.output;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;
import java.util.zip.CRC32;

import com.google.gson.JsonObject;

import ghidradwarfforge.output.ExportArtifactHashBinding.Agreement;
import ghidradwarfforge.output.ExportArtifactHashBinding.Artifact;
import ghidradwarfforge.output.ExportArtifactHashBinding.Result;
import ghidradwarfforge.output.ExportArtifactHashBindingFixtures.Pair;

/** Composition checks; lower-level parser/digest grammar and vectors have their own smokes. */
public final class ExportArtifactHashBindingSmoke {
    private static int checks;

    private ExportArtifactHashBindingSmoke() {
    }

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("forge-claim-binding-").toRealPath();
        try {
            normalAndMismatches(root.resolve("normal"));
            reportFirst(root.resolve("reports"));
            preconditions(root.resolve("preconditions"));
            failures(root.resolve("failures"));
            cancellation(root.resolve("cancellation"));
            traversalAndAliases(root.resolve("paths"));
            if (args.length == 1 && args[0].equals("--large")) {
                large(root.resolve("large"));
            }
            else if (args.length != 0) {
                throw new IllegalArgumentException("only optional --large is supported");
            }
            System.out.println("export-artifact-hash-binding-smoke=PASS checks=" + checks);
        }
        finally {
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                    Files.delete(path);
                }
            }
        }
    }

    private static void normalAndMismatches(Path root) throws Exception {
        for (boolean partial : List.of(false, true)) {
            Pair pair = ExportArtifactHashBindingFixtures.create(root.resolve("case-" + partial), partial);
            Map<Path, Snapshot> saved = snapshots(pair.all());
            Tracking access = new Tracking(pair);
            Result result = observe(pair, () -> false, access);
            require(result.claims().status() == (partial ? ExportReport.Status.PARTIAL :
                ExportReport.Status.SUCCESS), "reported completion status changed");
            require(result.claims().validationStatus() == ExportReport.ValidationStatus.NOT_RUN,
                "reported validation was upgraded");
            checkArtifacts(pair, result, 0);
            require(access.events.equals(List.of("attributes:report", "open:report", "close:report",
                "attributes:original", "attributes:sidecar", "attributes:source",
                "open:original", "close:original", "open:sidecar", "close:sidecar",
                "open:source", "close:source")), "report/precheck/digest order changed: " + access.events);
            access.closedExactly();
            require(observe(pair).equals(result), "repeated observation changed");
            unchanged(saved);

            byte[][] bytes = new byte[3][];
            for (int index = 0; index < 3; index++) {
                bytes[index] = Files.readAllBytes(pair.artifacts().get(index));
            }
            // Every nonempty subset: mismatches never prevent later roles from being observed.
            for (int mask = 1; mask < 8; mask++) {
                for (int index = 0; index < 3; index++) {
                    byte[] changed = bytes[index].clone();
                    if ((mask & (1 << index)) != 0) {
                        changed[0] ^= 0x5a;
                    }
                    Files.write(pair.artifacts().get(index), changed);
                }
                Map<Path, Snapshot> changed = snapshots(pair.all());
                checkArtifacts(pair, observe(pair), mask);
                unchanged(changed);
            }
            for (int index = 0; index < 3; index++) {
                Files.write(pair.artifacts().get(index), bytes[index]);
            }
            JsonObject json = ExportArtifactHashBindingFixtures.report(pair);
            JsonObject claims = json.getAsJsonObject("artifacts");
            for (String role : List.of("input", "output", "source")) {
                claims.addProperty(role + "Sha256", claims.get(role + "Sha256").getAsString()
                    .toUpperCase(java.util.Locale.ROOT));
            }
            claims.addProperty("inputPath", "Z:\\foreign\\not-selected.exe");
            claims.addProperty("outputPath", "/missing/never-open\u0000/sidecar");
            Path advertised = pair.root().resolve("advertised-source");
            if (java.io.File.separatorChar != '\\') {
                fifo(advertised);
            }
            claims.addProperty("sourcePath", advertised.toString());
            json.getAsJsonObject("target").addProperty("architecture", "unverified claim");
            Files.writeString(pair.report(), json.toString(), StandardCharsets.UTF_8);
            saved = snapshots(pair.all());
            result = observe(pair);
            checkArtifacts(pair, result, 0);
            require(result.claims().artifacts().inputPath().equals("Z:\\foreign\\not-selected.exe") &&
                result.claims().artifacts().outputPath().contains("\u0000") &&
                result.claims().artifacts().sourcePath().equals(advertised.toString()) &&
                result.claims().artifacts().inputSha256().equals(claims.get("inputSha256").getAsString()) &&
                result.claims().target().architecture().equals("unverified claim"),
                "opaque report paths/hash/target text changed");
            unchanged(saved);
            if (Files.exists(advertised)) {
                require(Files.readAttributes(advertised, BasicFileAttributes.class).isOther(),
                    "advertised FIFO was changed");
                Files.delete(advertised);
            }
            // Rewritten claims can agree with changed bytes; this is not validity/provenance.
            Files.writeString(pair.source(), "replacement plain data\n", StandardCharsets.UTF_8);
            ExportArtifactHashBindingFixtures.write(pair, partial);
            checkArtifacts(pair, observe(pair), 0);
        }
    }

    private static void reportFirst(Path root) throws Exception {
        Pair pair = ExportArtifactHashBindingFixtures.create(root, false);
        String completed = Files.readString(pair.report());
        for (ExportReport.Status status : List.of(ExportReport.Status.FATAL, ExportReport.Status.CANCELLED)) {
            Files.writeString(pair.report(), ExportReportClaimsFixtures.terminal(status).toJson());
            Tracking access = new Tracking(pair);
            var error = expect(ExportReportClaims.TerminalReportException.class,
                () -> observe(pair, () -> false, access));
            require(error.status() == status, "terminal status was lost");
            reportOnly(access);
        }
        JsonObject json = com.google.gson.JsonParser.parseString(completed).getAsJsonObject();
        json.getAsJsonObject("counts").remove("functionStaticVariables");
        Files.writeString(pair.report(), json.toString());
        Tracking historical = new Tracking(pair);
        expect(ExportReportClaims.UnsupportedReportShapeException.class,
            () -> observe(pair, () -> false, historical));
        reportOnly(historical);
        for (String invalid : List.of("{}", completed + " false",
                ExportReportClaimsFixtures.terminal(ExportReport.Status.FATAL).toJson()
                    .replace("\"target\":null", "\"target\":{}"))) {
            Files.writeString(pair.report(), invalid);
            Tracking access = new Tracking(pair);
            IOException error = expect(IOException.class, () -> observe(pair, () -> false, access));
            require(!(error instanceof ExportReportClaims.TerminalReportException),
                "malformed report became valid terminal outcome");
            reportOnly(access);
        }
        Files.writeString(pair.report(), completed);
        Path absent = root.resolve("absent");
        Pair missing = new Pair(root, absent, pair.original(), pair.sidecar(), pair.source());
        Tracking access = new Tracking(missing);
        expect(java.nio.file.NoSuchFileException.class, () -> observe(missing, () -> false, access));
        require(access.events.equals(List.of("attributes:report")), "missing report touched artifacts");
    }

    private static void preconditions(Path root) throws Exception {
        Pair pair = ExportArtifactHashBindingFixtures.create(root, false);
        for (int role = 0; role < 4; role++) {
            for (boolean missing : List.of(false, true)) {
                Path replaced = pair.all().get(role);
                byte[] bytes = Files.readAllBytes(replaced);
                Files.delete(replaced);
                if (!missing) {
                    Files.createDirectory(replaced);
                }
                Tracking access = new Tracking(pair);
                IOException error = expect(IOException.class, () -> observe(pair, () -> false, access));
                require(missing == (error instanceof java.nio.file.NoSuchFileException),
                    "missing/directory rejection type changed");
                require(access.streams.keySet().stream().allMatch(pair.report()::equals),
                    "artifact opened before all regular-file preconditions passed");
                access.closedExactly();
                if (!missing) {
                    Files.delete(replaced);
                }
                Files.write(replaced, bytes);
            }
        }
        if (java.io.File.separatorChar != '\\') {
            for (Path path : pair.all()) {
                byte[] bytes = Files.readAllBytes(path);
                Files.delete(path);
                fifo(path);
                Tracking access = new Tracking(pair);
                expect(IOException.class, () -> observe(pair, () -> false, access));
                require(!access.streams.containsKey(path) &&
                    access.streams.keySet().stream().allMatch(pair.report()::equals),
                    "known selected FIFO opened or artifact read before preflight");
                access.closedExactly();
                require(Files.readAttributes(path, BasicFileAttributes.class).isOther(),
                    "selected FIFO was mutated");
                Files.delete(path);
                Files.write(path, bytes);
            }
            System.out.println("selected-known-fifos-rejected=PASS");
        }
    }

    private static void failures(Path root) throws Exception {
        Pair pair = ExportArtifactHashBindingFixtures.create(root, false);
        Map<Path, Snapshot> saved = snapshots(pair.all());
        for (Path path : pair.all()) {
            for (String failure : List.of("attributes", "open", "read", "close", "read-close")) {
                Tracking access = new Tracking(pair);
                IOException primary = new IOException("injected " + failure);
                IOException close = new IOException("injected secondary close");
                access.failing = path;
                access.failure = failure;
                access.primary = primary;
                access.secondary = close;
                IOException actual = expect(IOException.class, () -> observe(pair, () -> false, access));
                require(actual == primary, "composition replaced primary IOException");
                require(Arrays.equals(actual.getSuppressed(), failure.equals("read-close")
                    ? new Throwable[] { close } : new Throwable[0]), "suppressed close failure lost");
                access.closedExactly();
                int failedOpen = access.events.indexOf("open:" + access.role(path));
                if (failedOpen >= 0) {
                    require(access.events.subList(failedOpen + 1, access.events.size()).stream()
                        .noneMatch(event -> event.startsWith("open:")), "reads continued after failure");
                }
            }
        }
        unchanged(saved);
    }

    private static void cancellation(Path root) throws Exception {
        Pair pair = ExportArtifactHashBindingFixtures.create(root, true);
        Tracking before = new Tracking(pair);
        expect(CancellationException.class, () -> observe(pair, () -> true, before));
        require(before.events.isEmpty(), "cancel before inspection accessed files");
        for (Path path : pair.all()) {
            for (String point : List.of("read", "eof", "closed")) {
                Tracking access = new Tracking(pair);
                BooleanSupplier cancelled = () -> access.reached(path, point);
                expect(CancellationException.class, () -> observe(pair, cancelled, access));
                access.closedExactly();
                require(access.streams.containsKey(path), "cancel point was not reached");
                int last = access.events.indexOf("close:" + access.role(path));
                require(last == access.events.size() - 1, "another file accessed after cancellation");
            }
        }
        Tracking afterPreflight = new Tracking(pair);
        expect(CancellationException.class, () -> observe(pair,
            () -> afterPreflight.events.contains("attributes:source"), afterPreflight));
        require(afterPreflight.streams.keySet().equals(java.util.Set.of(pair.report())),
            "cancel after preflight opened an artifact");
        afterPreflight.closedExactly();

        Tracking callback = new Tracking(pair);
        IllegalStateException failure = new IllegalStateException("supplier failed");
        require(expect(IllegalStateException.class, () -> observe(pair, () -> {
            if (callback.reached(pair.sidecar(), "read")) {
                throw failure;
            }
            return false;
        }, callback)) == failure, "supplier exception was replaced");
        callback.closedExactly();
        require(!callback.streams.containsKey(pair.source()), "source read after supplier failure");
        Tracking close = new Tracking(pair);
        close.failing = pair.original();
        close.failure = "close";
        close.primary = new IOException("close while cancelling");
        var cancelled = expect(CancellationException.class, () -> observe(pair,
            () -> close.reached(pair.original(), "read"), close));
        require(Arrays.equals(cancelled.getSuppressed(), new Throwable[] { close.primary }),
            "cancellation lost suppressed close failure");
        close.closedExactly();
    }

    private static void traversalAndAliases(Path root) throws Exception {
        Pair pair = ExportArtifactHashBindingFixtures.create(root.resolve("files"), false);
        Path logical = Files.createDirectory(root.resolve("logical"));
        Path actual = Files.createDirectory(root.resolve("actual"));
        Path child = Files.createDirectory(actual.resolve("child"));
        Files.createSymbolicLink(logical.resolve("link"), child);
        Files.writeString(logical.resolve("selected"), "logical-parent bytes");
        Files.writeString(actual.resolve("selected"), "actual-parent bytes");
        Path traversed = logical.resolve("link").resolve("..").resolve("selected");
        byte[] expected = Files.readAllBytes(traversed);
        JsonObject json = ExportArtifactHashBindingFixtures.report(pair);
        json.getAsJsonObject("artifacts").addProperty("inputSha256",
            ExportArtifactHashBindingFixtures.expected(expected).sha256());
        Files.writeString(pair.report(), json.toString());
        Pair selected = new Pair(root, pair.report(), traversed, pair.sidecar(), pair.source());
        Map<Path, Snapshot> saved = snapshots(List.of(pair.report(), logical.resolve("selected"),
            actual.resolve("selected"), pair.sidecar(), pair.source()));
        Result result = observe(selected);
        require(result.original().selectedPath().equals(traversed) &&
            result.original().selectedPath().toString().contains("..") &&
            result.original().agreement() == Agreement.MATCHING_REPORTED_SHA256 &&
            result.original().observed().equals(ExportArtifactHashBindingFixtures.expected(expected)),
            "raw host traversal or selected spelling was changed");
        unchanged(saved);
        System.out.println("host-traversal=" + System.getProperty("os.name") + " path=" + traversed);

        Path link = root.resolve("selected-link");
        Files.createSymbolicLink(link, pair.original());
        Path hard = root.resolve("selected-hardlink");
        Files.createLink(hard, pair.original());
        require(Files.isSameFile(link, hard), "alias control is not a real alias");
        Pair aliases = new Pair(root, pair.report(), pair.original(), link, hard);
        ExportArtifactHashBindingFixtures.write(aliases, false);
        result = observe(aliases);
        checkArtifacts(aliases, result, 0);
        require(Files.isSymbolicLink(link) && Files.isSameFile(hard, pair.original()),
            "read-only alias observation changed links");
        Pair same = new Pair(root, pair.report(), hard, hard, hard);
        ExportArtifactHashBindingFixtures.write(same, true);
        checkArtifacts(same, observe(same), 0);
    }

    private static void large(Path root) throws Exception {
        Pair pair = ExportArtifactHashBindingFixtures.create(root, false);
        long size = (1L << 31) + 65537;
        try (FileChannel channel = FileChannel.open(pair.original(), StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING)) {
            channel.write(ByteBuffer.wrap(new byte[] { 0x57 }), size - 1);
        }
        // Independent sparse recipe: zeros until the final byte; no whole-file allocation.
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        CRC32 crc = new CRC32();
        byte[] zeros = new byte[65536];
        long remaining = size - 1;
        while (remaining > 0) {
            int length = (int) Math.min(remaining, zeros.length);
            sha.update(zeros, 0, length);
            crc.update(zeros, 0, length);
            remaining -= length;
        }
        sha.update((byte) 0x57);
        crc.update(0x57);
        FileDigests.Result expected = new FileDigests.Result(
            HexFormat.of().formatHex(sha.digest()), crc.getValue(), size);
        JsonObject json = ExportArtifactHashBindingFixtures.report(pair);
        json.getAsJsonObject("artifacts").addProperty("inputSha256", expected.sha256());
        Files.writeString(pair.report(), json.toString());
        var modified = Files.getLastModifiedTime(pair.original());
        Result result = observe(pair);
        require(result.original().agreement() == Agreement.MATCHING_REPORTED_SHA256 &&
            result.original().observed().equals(expected), "large selected-file observation differs");
        require(Files.size(pair.original()) == size &&
            Files.getLastModifiedTime(pair.original()).equals(modified), "large input was modified");
        try (FileChannel channel = FileChannel.open(pair.original(), StandardOpenOption.READ)) {
            ByteBuffer tail = ByteBuffer.allocate(1);
            require(channel.read(tail, size - 1) == 1 && tail.array()[0] == 0x57,
                "large sparse sentinel changed");
        }
        System.out.println("large-selected-bytes=" + size + " sha256=" + expected.sha256());
    }

    private static Result observe(Pair pair) throws IOException {
        return ExportArtifactHashBinding.observe(pair.report(), pair.original(), pair.sidecar(), pair.source());
    }

    private static Result observe(Pair pair, BooleanSupplier cancelled, Tracking access) throws IOException {
        return ExportArtifactHashBinding.observe(pair.report(), pair.original(), pair.sidecar(), pair.source(),
            cancelled, access);
    }

    private static void checkArtifacts(Pair pair, Result result, int mismatches) throws Exception {
        List<Artifact> artifacts = List.of(result.original(), result.sidecar(), result.source());
        for (int index = 0; index < artifacts.size(); index++) {
            Artifact artifact = artifacts.get(index);
            require(artifact.selectedPath().equals(pair.artifacts().get(index)), "selected path spelling changed");
            require(artifact.observed().equals(ExportArtifactHashBindingFixtures.expected(
                Files.readAllBytes(pair.artifacts().get(index)))), "observed digest/count differs");
            require(artifact.agreement() == ((mismatches & (1 << index)) == 0
                ? Agreement.MATCHING_REPORTED_SHA256 : Agreement.DIFFERENT_REPORTED_SHA256),
                "role mismatch classification differs");
        }
    }

    private static void reportOnly(Tracking access) {
        require(access.events.equals(List.of("attributes:report", "open:report", "close:report")),
            "invalid/terminal report inspected artifacts: " + access.events);
        access.closedExactly();
    }

    private static void fifo(Path path) throws Exception {
        Process process = new ProcessBuilder("mkfifo", path.toString()).start();
        require(process.waitFor() == 0 && Files.readAttributes(path, BasicFileAttributes.class).isOther(),
            "owned FIFO setup failed");
    }

    private record Snapshot(byte[] bytes, java.nio.file.attribute.FileTime modified) {
    }

    private static Map<Path, Snapshot> snapshots(List<Path> paths) throws Exception {
        Map<Path, Snapshot> saved = new HashMap<>();
        for (Path path : paths) {
            saved.put(path, new Snapshot(Files.readAllBytes(path), Files.getLastModifiedTime(path)));
        }
        return saved;
    }

    private static void unchanged(Map<Path, Snapshot> saved) throws Exception {
        for (var entry : saved.entrySet()) {
            require(Arrays.equals(Files.readAllBytes(entry.getKey()), entry.getValue().bytes()) &&
                Files.getLastModifiedTime(entry.getKey()).equals(entry.getValue().modified()),
                "observation changed selected bytes/mtime: " + entry.getKey());
        }
    }

    private static final class Tracking implements ExportArtifactHashBinding.FileAccess {
        final Pair pair;
        final List<String> events = new ArrayList<>();
        final Map<Path, TrackedInput> streams = new HashMap<>();
        Path failing;
        String failure;
        IOException primary;
        IOException secondary;

        Tracking(Pair pair) {
            this.pair = pair;
        }

        String role(Path path) {
            int index = pair.all().indexOf(path);
            return List.of("report", "original", "sidecar", "source").get(index);
        }

        @Override
        public BasicFileAttributes attributes(Path path) throws IOException {
            events.add("attributes:" + role(path));
            if (path.equals(failing) && "attributes".equals(failure)) {
                throw primary;
            }
            return Files.readAttributes(path, BasicFileAttributes.class);
        }

        @Override
        public InputStream open(Path path) throws IOException {
            events.add("open:" + role(path));
            if (path.equals(failing) && "open".equals(failure)) {
                throw primary;
            }
            TrackedInput stream = new TrackedInput(Files.newInputStream(path), path, this);
            streams.put(path, stream);
            return stream;
        }

        boolean reached(Path path, String point) {
            TrackedInput stream = streams.get(path);
            return stream != null && switch (point) {
                case "read" -> stream.reads > 0;
                case "eof" -> stream.eof;
                case "closed" -> stream.closes > 0;
                default -> throw new AssertionError("unknown point");
            };
        }

        void closedExactly() {
            for (TrackedInput stream : streams.values()) {
                require(stream.closes == 1, "owned stream was not closed exactly once");
            }
        }
    }

    private static final class TrackedInput extends FilterInputStream {
        final Path path;
        final Tracking access;
        int reads;
        int closes;
        boolean eof;

        TrackedInput(InputStream input, Path path, Tracking access) {
            super(input);
            this.path = path;
            this.access = access;
        }

        @Override
        public int read(byte[] bytes, int offset, int length) throws IOException {
            reads++;
            if (path.equals(access.failing) &&
                    List.of("read", "read-close").contains(access.failure)) {
                throw access.primary;
            }
            int count = in.read(bytes, offset, length);
            eof |= count == -1;
            return count;
        }

        @Override
        public void close() throws IOException {
            closes++;
            access.events.add("close:" + access.role(path));
            super.close();
            if (path.equals(access.failing)) {
                if ("close".equals(access.failure)) {
                    throw access.primary;
                }
                if ("read-close".equals(access.failure)) {
                    throw access.secondary;
                }
            }
        }
    }

    @FunctionalInterface
    private interface Checked {
        void run() throws Exception;
    }

    private static <T extends Throwable> T expect(Class<T> type, Checked action) throws Exception {
        try {
            action.run();
        }
        catch (Throwable failure) {
            require(type.isInstance(failure), "unexpected failure: " + failure);
            return type.cast(failure);
        }
        throw new AssertionError("expected " + type.getName());
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
