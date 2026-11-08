package ghidradwarfforge.output;

import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import ghidradwarfforge.elf.ElfBuildId;
import ghidradwarfforge.elf.SyntheticSourceSidecar;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

import static ghidradwarfforge.output.BuildIdRecords.*;

/**
 * Explicit build-ID installation, update, removal and interrupted-publication reconciliation.
 * The executable is only observed. A mandatory host supplies metadata, atomic names and sync;
 * a mandatory production validator checks the derived artifact before a searchable name exists.
 * This internal API is not a platform host implementation or a public command-line launcher.
 *
 * Generations and operation directories are retained, including incomplete preparations. Removal
 * moves the verified registration to an owned tombstone; it never prunes source generations.
 * Locks serialize cooperating processes. Checks detect ordinary concurrent changes, not hostile
 * change-and-restore races between filesystem observations and an operation.
 */
public final class BuildIdInstallation {
    public enum Mode { INSTALL, UPDATE, REMOVE }
    public enum Outcome { INSTALLED, UPDATED, REMOVED, ALREADY_INSTALLED, RECOVERED_COMMIT, RECOVERED_ABORT, UNCHANGED }

    public record Request(Path root, Path original, Path sidecar, Path source, Path report, Mode mode) {
        public Request {
            java.util.Objects.requireNonNull(root);
            java.util.Objects.requireNonNull(original);
            java.util.Objects.requireNonNull(sidecar);
            java.util.Objects.requireNonNull(source);
            java.util.Objects.requireNonNull(report);
            if (mode != Mode.INSTALL && mode != Mode.UPDATE) throw new IllegalArgumentException("use remove for removal");
        }
    }

    public record Result(Outcome outcome, String buildId, Path registration, Path source, Path state) { }

    enum Boundary { GENERATION_SEALED, PREPARED, BEFORE_PUBLICATION, PUBLISHED, COMMITTED }
    @FunctionalInterface interface Hook { void at(Boundary boundary) throws IOException; }
    private static final Hook NO_HOOK = boundary -> { };
    private static final String SCHEMA = "forge-build-id-state-v1";
    private static final String GENERATION = "forge-build-id-generation-v1";
    // Two independent source inventories: reported export and relocated consumer.
    // Allow the complete 65,536-part source policy plus existing validator evidence.
    private static final int MAX_GENERATION_FILES = 512 + 2 * (65536 + 1);
    private static final int MAX_GENERATION_ENTRIES = MAX_GENERATION_FILES + 256;

    private BuildIdInstallation() { }

    public static Result install(Request request, AttachmentOperation.Host host, AttachmentValidator validator,
            BooleanSupplier cancelled) throws IOException {
        return install(request, host, validator, cancelled, NO_HOOK);
    }

    static Result install(Request request, AttachmentOperation.Host host, AttachmentValidator validator,
            BooleanSupplier cancelled, Hook hook) throws IOException {
        java.util.Objects.requireNonNull(validator, "live production validator");
        var export = AttachmentExportBinding.observe(request.report(), request.original(), request.sidecar(),
            request.source(), host, cancelled);
        String id = ElfBuildId.read(export.files().get("exportOriginal").path(), cancelled).hex()
            .orElseThrow(() -> new IOException("original has no build ID; use explicit GDB loading or opt-in debuglink attachment"));
        validateId(id);
        try (var session = Session.open(request.root(), id, host, cancelled)) {
            session.rejectInputAliases(export);
            JsonObject previous = session.readState();
            session.requireSettled(previous);
            JsonObject current = current(previous);
            String originalSha = export.files().get("exportOriginal").digest().sha256();
            session.originalSha = originalSha;
            if (previous != null) require(originalSha.equals(text(previous, "originalSha256")),
                "build ID was previously associated with different original bytes");
            session.verifyCurrent(current);
            String key = generationKey(originalSha, export.files().get("sidecar").digest().sha256(),
                export.files().get("source").digest().sha256());
            if (current != null) {
                JsonObject manifest = session.generation(current);
                if (key.equals(text(manifest, "contentKey"))) {
                    export.recheck(host, cancelled);
                    return session.result(Outcome.ALREADY_INSTALLED, current);
                }
                require(request.mode() == Mode.UPDATE, "a different export is installed; an explicit update is required");
            }
            else require(request.mode() == Mode.INSTALL, "no managed installation exists to update");

            String operation = UUID.randomUUID().toString();
            Path transaction = session.newTransaction(operation);
            if (previous != null) AttachmentFileStore.backup(session.stateSnapshot, transaction.resolve("previous-state.json"), host, cancelled);
            Path generation = session.generations.resolve(operation);
            Files.createDirectory(generation);
            host.syncDirectory(session.generations);
            Path retained = Files.createDirectory(generation.resolve("source"));
            host.syncDirectory(generation);
            var reportedSidecar = AttachmentFileStore.backup(export.files().get("sidecar"), generation.resolve("export.dbg"), host, cancelled);
            var reportedSource = AttachmentFileStore.backup(export.files().get("source"), generation.resolve("export.source"), host, cancelled);
            var report = AttachmentFileStore.backup(export.files().get("exportReport"), generation.resolve("export.json"), host, cancelled);
            for (var dependency : export.sourceDependencies()) {
                String name = dependency.path().getFileName().toString();
                var saved = AttachmentFileStore.backup(dependency, generation.resolve(name), host, cancelled);
                AttachmentFileStore.backup(saved, retained.resolve(name), host, cancelled);
            }
            String directory = retained.toString();
            if (java.io.File.separatorChar == '\\') directory = directory.replace('\\', '/');
            var relocation = SyntheticSourceSidecar.prepare(reportedSidecar.path(), directory, cancelled);
            Path source = relative(retained, relocation.fileName());
            require(source.getParent().equals(retained), "synthetic source name must be a leaf");
            AttachmentFileStore.backup(reportedSource, source, host, cancelled);
            Path derived = generation.resolve("installed.debug");
            try (FileChannel output = FileChannel.open(derived, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                relocation.writeStage(output, cancelled);
                host.preserveMetadata(reportedSidecar.path(), reportedSidecar.fingerprint(), derived);
                output.force(true);
            }
            host.syncDirectory(generation);
            var retainedExport = AttachmentExportBinding.observe(report.path(), export.files().get("exportOriginal").path(),
                reportedSidecar.path(), reportedSource.path(), relocation.fileName(), host, cancelled);
            var binding = ArtifactValidationBinding.relocated(retainedExport, derived, source, host, cancelled);
            validator.validate(binding, generation.resolve("validation.json"), host, cancelled);
            binding.recheck(host, cancelled);
            export.recheck(host, cancelled);
            JsonObject manifest = session.sealGeneration(generation, originalSha, key, relocation.fileName());
            var manifestFile = AttachmentFileStore.observe(generation.resolve("generation.json"), host, cancelled);
            hook.at(Boundary.GENERATION_SEALED);
            // Select access metadata before sealing the new copy. Reopening a
            // completed read-only copy for writing would make explicit refresh fail.
            var metadataSource = current == null ? binding.files().get("sidecar") :
                snapshot(object(current, "registration"), session.registration);
            var stage = AttachmentFileStore.copyWithMetadata(binding.files().get("sidecar"), metadataSource,
                transaction.resolve("publish.debug"), host, cancelled);
            JsonObject next = new JsonObject();
            next.addProperty("generation", operation);
            next.add("manifest", snapshot(manifestFile));
            next.add("registration", snapshot(stage));
            session.verifyGeneration(next, manifest);
            export.recheck(host, cancelled);
            JsonObject prepared = session.prepare(previous, request.mode(), operation, originalSha, current, next);
            hook.at(Boundary.PREPARED);
            check(cancelled);
            export.recheck(host, cancelled);
            session.verifyCurrent(current);
            session.generation(next);
            AttachmentFileStore.unchanged(stage, host, cancelled);
            session.recheckState();
            session.recheckDirectories();
            hook.at(Boundary.BEFORE_PUBLICATION);
            check(cancelled);
            session.verifyCurrent(current);
            AttachmentFileStore.unchanged(stage, host, cancelled);
            session.recheckState();
            session.recheckDirectories();
            session.finishing = true;
            if (current == null) host.publishNew(stage.path(), session.registration);
            else host.replaceAtomic(stage.path(), session.registration);
            hook.at(Boundary.PUBLISHED);
            // Once published, finish sync/readback regardless of late cancellation.
            session.completePublication(prepared, transaction, next);
            hook.at(Boundary.COMMITTED);
            return session.result(current == null ? Outcome.INSTALLED : Outcome.UPDATED, next);
        }
    }

    public static Result remove(Path root, String buildId, AttachmentOperation.Host host, BooleanSupplier cancelled)
            throws IOException {
        return remove(root, buildId, host, cancelled, NO_HOOK);
    }

    static Result remove(Path root, String buildId, AttachmentOperation.Host host, BooleanSupplier cancelled, Hook hook)
            throws IOException {
        try (var session = Session.open(root, buildId, host, cancelled)) {
            JsonObject previous = session.readState();
            session.requireSettled(previous);
            JsonObject current = current(previous);
            require(current != null, "no managed installation exists to remove");
            session.verifyCurrent(current);
            String operation = UUID.randomUUID().toString();
            Path transaction = session.newTransaction(operation);
            AttachmentFileStore.backup(session.stateSnapshot, transaction.resolve("previous-state.json"), host, cancelled);
            JsonObject prepared = session.prepare(previous, Mode.REMOVE, operation, text(previous, "originalSha256"), current, null);
            hook.at(Boundary.PREPARED);
            session.verifyCurrent(current);
            session.recheckState();
            session.recheckDirectories();
            hook.at(Boundary.BEFORE_PUBLICATION);
            check(cancelled);
            session.verifyCurrent(current);
            session.recheckState();
            session.recheckDirectories();
            session.finishing = true;
            host.publishNew(session.registration, transaction.resolve("retired.debug"));
            hook.at(Boundary.PUBLISHED);
            session.completePublication(prepared, transaction, null);
            hook.at(Boundary.COMMITTED);
            return session.result(Outcome.REMOVED, null);
        }
    }

    /** Finalize an observed publication, or abort an unapplied intent; never publish a cancelled preparation. */
    public static Result recover(Path root, String buildId, AttachmentOperation.Host host, BooleanSupplier cancelled)
            throws IOException {
        try (var session = Session.open(root, buildId, host, cancelled)) {
            JsonObject state = session.readState();
            if (state == null) {
                absent(session.registration);
                return session.result(Outcome.UNCHANGED, null);
            }
            if (!text(state, "phase").equals("PREPARED")) {
                session.verifyCurrent(current(state));
                return session.result(Outcome.UNCHANGED, current(state));
            }
            JsonObject before = nullableObject(state, "before"), after = nullableObject(state, "after");
            if (before != null) session.generation(before);
            if (after != null) session.generation(after);
            Path transaction = session.transactions.resolve(text(state, "operationId"));
            session.directory(transaction);
            if (session.matchesRegistration(after)) {
                if (after == null) AttachmentFileStore.unchanged(snapshot(object(before, "registration"),
                    transaction.resolve("retired.debug")), host, cancelled);
                else absent(transaction.resolve("publish.debug"));
                session.completePublication(state, transaction, after);
                return session.result(Outcome.RECOVERED_COMMIT, after);
            }
            require(session.matchesRegistration(before), "registration matches neither prepared state; manual reconciliation required");
            if (after != null) AttachmentFileStore.unchanged(snapshot(object(after, "registration"),
                transaction.resolve("publish.debug")), host, cancelled);
            else absent(transaction.resolve("retired.debug"));
            JsonObject aborted = state.deepCopy();
            aborted.addProperty("phase", "ABORTED");
            session.writeState(aborted);
            return session.result(Outcome.RECOVERED_ABORT, before);
        }
    }

    private static final class Session implements AutoCloseable {
        final Path root, namespace, generations, transactions, registration, statePath;
        final String id;
        final AttachmentOperation.Host host;
        final BooleanSupplier cancelled;
        final Map<Path, String> directories = new LinkedHashMap<>();
        BuildIdFileLock lock;
        AttachmentFileStore.Snapshot stateSnapshot;
        Path transactionPath;
        String transactionIdentity;
        String originalSha;
        boolean finishing;

        BooleanSupplier verificationCancellation() { return finishing ? () -> false : cancelled; }

        private Session(Path root, String id, AttachmentOperation.Host host, BooleanSupplier cancelled) throws IOException {
            this.root = root.toRealPath();
            this.id = id;
            this.host = java.util.Objects.requireNonNull(host);
            this.cancelled = java.util.Objects.requireNonNull(cancelled);
            require(Files.isDirectory(this.root, LinkOption.NOFOLLOW_LINKS), "debug root must be an existing directory");
            directories.put(this.root, host.directoryIdentity(this.root));
            Path buildIds = childDirectory(this.root, ".build-id");
            Path prefix = childDirectory(buildIds, id.substring(0, 2));
            registration = prefix.resolve(id.substring(2) + ".debug");
            Path managed = childDirectory(this.root, ".forge-build-id");
            Path version = childDirectory(managed, "v1");
            namespace = childDirectory(version, id);
            generations = childDirectory(namespace, "generations");
            transactions = childDirectory(namespace, "transactions");
            statePath = namespace.resolve("state.json");
        }

        static Session open(Path root, String id, AttachmentOperation.Host host, BooleanSupplier cancelled) throws IOException {
            validateId(id);
            check(cancelled);
            var session = new Session(root, id, host, cancelled);
            try { session.acquire(); return session; }
            catch (IOException | RuntimeException failure) {
                try { session.close(); } catch (IOException cleanup) { failure.addSuppressed(cleanup); }
                throw failure;
            }
        }

        void acquire() throws IOException {
            Path path = namespace.resolve("lock");
            byte[] magic = ("Forge build-ID lock v1\n" + id + "\n").getBytes(StandardCharsets.UTF_8);
            if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
                Path stage = Files.createTempFile(namespace, ".lock-", ".stage");
                try (FileChannel out = FileChannel.open(stage, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)) {
                    write(out, magic); out.force(true);
                }
                try { host.publishNew(stage, path); }
                catch (IOException collision) {
                    // Only an independently verified, concurrently published lock is usable.
                    if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) throw collision;
                }
                host.syncDirectory(namespace);
            }
            lock = BuildIdFileLock.acquire(path, magic, host, cancelled);
            recheckDirectories();
        }

        Path childDirectory(Path parent, String leaf) throws IOException {
            check(cancelled);
            Path path = parent.resolve(leaf);
            try { Files.createDirectory(path); host.syncDirectory(parent); }
            catch (FileAlreadyExistsException existing) { /* Independently inspect the existing directory below. */ }
            directories.put(path, directory(path));
            return path;
        }

        String directory(Path path) throws IOException {
            require(Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(path), "managed path is not a non-link directory: " + path);
            return host.directoryIdentity(path);
        }

        void recheckDirectories() throws IOException {
            for (var entry : directories.entrySet()) require(entry.getValue().equals(directory(entry.getKey())), "installation directory changed: " + entry.getKey());
            if (transactionPath != null) require(transactionIdentity.equals(directory(transactionPath)), "installation transaction directory changed");
            if (lock != null) lock.verify(verificationCancellation());
        }

        void rejectInputAliases(AttachmentExportBinding export) throws IOException {
            var inputs = new ArrayList<>(export.files().values());
            inputs.addAll(export.sourceDependencies());
            for (var file : inputs) {
                for (Path managed : List.of(registration, statePath, namespace.resolve("lock"))) {
                    require(!file.path().equals(managed) && (!Files.exists(managed, LinkOption.NOFOLLOW_LINKS) ||
                        !Files.isSameFile(file.path(), managed)), "selected input aliases an installation control/output file");
                }
            }
        }

        JsonObject readState() throws IOException {
            recheckDirectories();
            if (!Files.exists(statePath, LinkOption.NOFOLLOW_LINKS)) { stateSnapshot = null; return null; }
            stateSnapshot = AttachmentFileStore.observe(statePath, host, cancelled);
            JsonObject state = BuildIdRecords.read(statePath, cancelled);
            keys(state, "schema", "buildId", "rootPath", "hostContract", "durability", "directories", "transactionDirectory", "originalSha256", "operationId", "mode", "phase", "before", "after");
            require(text(state, "schema").equals(SCHEMA) && text(state, "buildId").equals(id) &&
                text(state, "hostContract").equals(host.contract()) && text(state, "durability").equals(host.durability()), "installation record contract differs");
            require(text(state, "rootPath").equals(root.toString()), "debug root moved; retained DWARF source paths require a new installation in a fresh root");
            originalSha = text(state, "originalSha256");
            hash(originalSha); uuid(text(state, "operationId"));
            transactionPath = transactions.resolve(text(state, "operationId"));
            transactionIdentity = text(state, "transactionDirectory");
            recheckDirectories();
            String phase = text(state, "phase"), mode = text(state, "mode");
            require(List.of("PREPARED", "COMMITTED", "ABORTED").contains(phase), "unknown installation phase");
            JsonObject before = nullableObject(state, "before"), after = nullableObject(state, "after");
            require(mode.equals("INSTALL") && before == null && after != null ||
                mode.equals("UPDATE") && before != null && after != null ||
                mode.equals("REMOVE") && before != null && after == null, "invalid installation transition");
            if (before != null) validateInstallation(before);
            if (after != null) {
                validateInstallation(after);
                require(text(after, "generation").equals(text(state, "operationId")), "prepared generation differs from operation");
            }
            require(object(state, "directories").equals(directoryRecord()), "recorded installation directories changed");
            recheckState();
            return state;
        }

        void requireSettled(JsonObject state) throws IOException {
            require(state == null || !text(state, "phase").equals("PREPARED"), "interrupted build-ID operation requires explicit recovery: " + statePath);
        }

        Path newTransaction(String operation) throws IOException {
            recheckDirectories();
            Path path = transactions.resolve(operation);
            Files.createDirectory(path);
            host.syncDirectory(transactions);
            transactionPath = path;
            transactionIdentity = directory(path);
            return path;
        }

        JsonObject prepare(JsonObject previous, Mode mode, String operation, String originalSha,
                JsonObject before, JsonObject after) throws IOException {
            if (previous == null) require(stateSnapshot == null, "unexpected state observation");
            else recheckState();
            var state = new JsonObject();
            state.addProperty("schema", SCHEMA); state.addProperty("buildId", id);
            state.addProperty("rootPath", root.toString());
            state.addProperty("hostContract", host.contract()); state.addProperty("durability", host.durability());
            state.add("directories", directoryRecord());
            state.addProperty("transactionDirectory", transactionIdentity);
            state.addProperty("originalSha256", originalSha); state.addProperty("operationId", operation);
            state.addProperty("mode", mode.name()); state.addProperty("phase", "PREPARED");
            state.add("before", before == null ? JsonNull.INSTANCE : before.deepCopy());
            state.add("after", after == null ? JsonNull.INSTANCE : after.deepCopy());
            writeState(state);
            return state;
        }

        JsonObject directoryRecord() {
            var record = new JsonObject();
            for (var entry : directories.entrySet()) record.addProperty(entry.getKey().equals(root) ? "." : root.relativize(entry.getKey()).toString(), entry.getValue());
            return record;
        }

        void recheckState() throws IOException {
            if (stateSnapshot == null) absent(statePath);
            else AttachmentFileStore.unchanged(stateSnapshot, host, verificationCancellation());
        }

        void writeState(JsonObject state) throws IOException {
            recheckDirectories(); recheckState();
            stateSnapshot = writeRecord(statePath, state, stateSnapshot, host);
        }

        void completePublication(JsonObject prepared, Path transaction, JsonObject next) throws IOException {
            finishing = true;
            host.syncDirectory(registration.getParent());
            host.syncDirectory(transaction);
            recheckDirectories();
            require(matchesRegistration(next), "published registration differs from prepared bytes/identity");
            if (next == null) AttachmentFileStore.unchanged(snapshot(object(object(prepared, "before"), "registration"),
                transaction.resolve("retired.debug")), host, verificationCancellation());
            else absent(transaction.resolve("publish.debug"));
            if (next != null) generation(next);
            var committed = prepared.deepCopy(); committed.addProperty("phase", "COMMITTED");
            writeState(committed);
        }

        void verifyCurrent(JsonObject current) throws IOException {
            if (current != null) generation(current);
            require(matchesRegistration(current), "registration is foreign, absent, aliased or modified");
        }

        boolean matchesRegistration(JsonObject installation) throws IOException {
            if (installation == null) return !Files.exists(registration, LinkOption.NOFOLLOW_LINKS);
            if (!Files.exists(registration, LinkOption.NOFOLLOW_LINKS)) return false;
            return snapshot(object(installation, "registration"), registration).equals(
                AttachmentFileStore.observe(registration, host, verificationCancellation()));
        }

        JsonObject sealGeneration(Path generation, String originalSha, String key, String sourceName) throws IOException {
            var manifest = new JsonObject();
            manifest.addProperty("schema", GENERATION); manifest.addProperty("buildId", id);
            manifest.addProperty("originalSha256", originalSha); manifest.addProperty("contentKey", key);
            manifest.addProperty("sourceName", sourceName);
            manifest.add("directories", generationDirectories(generation));
            var files = new JsonObject();
            for (Path path : generationFiles(generation)) {
                files.add(generation.relativize(path).toString(), snapshot(AttachmentFileStore.observe(path, host, cancelled)));
            }
            manifest.add("files", files);
            // Flush every retained directory before the seal can authorize publication.
            try (var paths = Files.walk(generation)) {
                for (Path path : paths.filter(p -> Files.isDirectory(p, LinkOption.NOFOLLOW_LINKS)).sorted(java.util.Comparator.reverseOrder()).toList()) host.syncDirectory(path);
            }
            writeRecord(generation.resolve("generation.json"), manifest, null, host, BuildIdRecords.GENERATION_MAX_BYTES);
            return manifest;
        }

        JsonObject generation(JsonObject installation) throws IOException {
            validateInstallation(installation);
            Path path = generations.resolve(text(installation, "generation")).resolve("generation.json");
            var observed = snapshot(object(installation, "manifest"), path);
            AttachmentFileStore.unchanged(observed, host, verificationCancellation());
            JsonObject manifest = BuildIdRecords.readGeneration(path, verificationCancellation());
            verifyGeneration(installation, manifest);
            AttachmentFileStore.unchanged(observed, host, verificationCancellation());
            return manifest;
        }

        void verifyGeneration(JsonObject installation, JsonObject manifest) throws IOException {
            keys(manifest, "schema", "buildId", "originalSha256", "contentKey", "sourceName", "directories", "files");
            require(text(manifest, "schema").equals(GENERATION) && text(manifest, "buildId").equals(id), "generation identity differs");
            hash(text(manifest, "originalSha256")); hash(text(manifest, "contentKey"));
            require(originalSha == null || originalSha.equals(text(manifest, "originalSha256")), "generation original differs from installation state");
            Path base = generations.resolve(text(installation, "generation"));
            directory(base);
            Path source = relative(base.resolve("source"), text(manifest, "sourceName"));
            require(source.getParent().equals(base.resolve("source")), "retained source must be a leaf");
            JsonObject files = object(manifest, "files");
            require(files.size() <= MAX_GENERATION_FILES && files.has("export.json") && files.has("export.dbg") && files.has("export.source") &&
                files.has("installed.debug") && files.has("validation.json") && files.has(base.relativize(source).toString()), "generation inventory is incomplete");
            var actual = new java.util.HashSet<String>();
            for (Path file : generationFiles(base)) if (!file.equals(base.resolve("generation.json"))) actual.add(base.relativize(file).toString());
            require(files.keySet().equals(actual), "generation file inventory changed");
            require(object(manifest, "directories").equals(generationDirectories(base)), "generation directories changed");
            for (String name : files.keySet()) AttachmentFileStore.unchanged(snapshot(object(files, name), relative(base, name)), host, verificationCancellation());
            var derived = snapshot(object(files, "installed.debug"), base.resolve("installed.debug"));
            require(derived.digest().equals(snapshot(object(installation, "registration"), registration).digest()), "registration does not describe retained sidecar");
            require(text(manifest, "contentKey").equals(generationKey(text(manifest, "originalSha256"),
                text(object(files, "export.dbg"), "sha256"), text(object(files, "export.source"), "sha256"))), "generation key differs from retained inputs");
            require(object(files, base.relativize(source).toString()).get("sha256").equals(object(files, "export.source").get("sha256")), "retained source hash differs");
        }

        List<Path> generationFiles(Path generation) throws IOException {
            var files = new ArrayList<Path>();
            try (var paths = Files.walk(generation)) {
                var iterator = paths.iterator(); int entries = 0;
                while (iterator.hasNext()) {
                    check(verificationCancellation());
                    Path path = iterator.next();
                    require(++entries <= MAX_GENERATION_ENTRIES, "generation exceeds entry limit");
                    require(!Files.isSymbolicLink(path), "generation contains a symbolic link");
                    if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) continue;
                    require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS), "generation contains a non-regular file");
                    files.add(path);
                }
            }
            files.sort(Path::compareTo);
            return files;
        }

        JsonObject generationDirectories(Path generation) throws IOException {
            var sorted = new TreeMap<String, String>();
            try (var paths = Files.walk(generation)) {
                var iterator = paths.iterator(); int entries = 0;
                while (iterator.hasNext()) {
                    check(verificationCancellation());
                    Path path = iterator.next();
                    require(++entries <= MAX_GENERATION_ENTRIES && !Files.isSymbolicLink(path), "invalid generation directory tree");
                    if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) sorted.put(path.equals(generation) ? "." : generation.relativize(path).toString(), directory(path));
                }
            }
            var result = new JsonObject(); sorted.forEach(result::addProperty); return result;
        }

        Result result(Outcome outcome, JsonObject installed) throws IOException {
            Path source = null;
            if (installed != null) {
                JsonObject manifest = generation(installed);
                source = relative(generations.resolve(text(installed, "generation")).resolve("source"), text(manifest, "sourceName"));
            }
            return new Result(outcome, id, registration, source, statePath);
        }

        @Override public void close() throws IOException {
            if (lock != null) lock.close();
        }
    }

    private static AttachmentFileStore.Snapshot writeRecord(Path destination, JsonObject record,
            AttachmentFileStore.Snapshot previous, AttachmentOperation.Host host) throws IOException {
        return writeRecord(destination, record, previous, host, 1024 * 1024);
    }

    private static AttachmentFileStore.Snapshot writeRecord(Path destination, JsonObject record,
            AttachmentFileStore.Snapshot previous, AttachmentOperation.Host host, int maximumBytes) throws IOException {
        byte[] bytes = (record + "\n").getBytes(StandardCharsets.UTF_8);
        require(bytes.length <= maximumBytes, "installation record exceeds byte limit: " + maximumBytes);
        Path stage = Files.createTempFile(destination.getParent(), ".record-", ".stage");
        try (FileChannel out = FileChannel.open(stage, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)) {
            write(out, bytes);
            if (previous != null) host.preserveMetadata(previous.path(), previous.fingerprint(), stage);
            out.force(true);
        }
        var staged = AttachmentFileStore.observe(stage, host, () -> false);
        if (previous == null) { absent(destination); host.publishNew(stage, destination); }
        else { AttachmentFileStore.unchanged(previous, host, () -> false); host.replaceAtomic(stage, destination); }
        host.syncDirectory(destination.getParent());
        var installed = AttachmentFileStore.observe(destination, host, () -> false);
        require(staged.digest().equals(installed.digest()) && staged.fingerprint().equals(installed.fingerprint()), "record publication changed bytes or identity");
        return installed;
    }

    private static void write(FileChannel channel, byte[] bytes) throws IOException {
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        while (buffer.hasRemaining()) require(channel.write(buffer) > 0, "installation write stopped making progress");
    }

    private static JsonObject nullableObject(JsonObject parent, String name) throws IOException {
        require(parent.has(name), "missing installation field: " + name);
        return parent.get(name).isJsonNull() ? null : object(parent, name);
    }

    private static JsonObject current(JsonObject state) throws IOException {
        if (state == null) return null;
        require(!text(state, "phase").equals("PREPARED"), "installation recovery is required");
        return nullableObject(state, text(state, "phase").equals("ABORTED") ? "before" : "after");
    }

    private static void validateInstallation(JsonObject installation) throws IOException {
        keys(installation, "generation", "manifest", "registration");
        uuid(text(installation, "generation"));
        snapshot(object(installation, "manifest"), Path.of("generation.json"));
        snapshot(object(installation, "registration"), Path.of("installed.debug"));
    }

    static void validateId(String id) throws IOException {
        require(id != null && id.matches("[0-9a-f]{2,248}") && (id.length() & 1) == 0,
            "build ID must be canonical lowercase hex and fit the supported 1..124-byte filename profile");
    }

    private static void uuid(String value) throws IOException {
        try { require(UUID.fromString(value).toString().equals(value), "noncanonical installation UUID"); }
        catch (IllegalArgumentException invalid) { throw new IOException("invalid installation UUID", invalid); }
    }

    private static void hash(String value) throws IOException { require(value.matches("[0-9a-f]{64}"), "invalid installation content hash"); }

    private static String generationKey(String original, String sidecar, String source) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(
                (GENERATION + "\n" + original + "\n" + sidecar + "\n" + source + "\n").getBytes(StandardCharsets.US_ASCII)));
        }
        catch (NoSuchAlgorithmException impossible) { throw new AssertionError(impossible); }
    }

    private static void absent(Path path) throws IOException {
        require(!Files.exists(path, LinkOption.NOFOLLOW_LINKS), "installation destination already exists: " + path);
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("build-ID installation cancelled");
    }
}
