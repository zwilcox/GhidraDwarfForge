package ghidradwarfforge.output;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.function.BooleanSupplier;
import ghidradwarfforge.source.SourcePartitionPlan;

/** Reads and verifies an entire immutable source bundle selected by its mutable synthetic index. */
public final class SourceBundleFiles {
    private static final byte[] PREFIX = SourceBundle.INDEX_PREFIX.getBytes(StandardCharsets.UTF_8);
    private static final int MAX_INDEX = 16 * 1024 * 1024;
    private static final int MAX_MANIFEST = 64 * 1024 * 1024;
    private record File(Path path, SourceBundleStore.State state) { }
    private record Bytes(byte[] bytes, File file) { }

    private final SourceBundle.Manifest manifest;
    private final List<File> files;

    private SourceBundleFiles(SourceBundle.Manifest manifest, List<File> files) {
        this.manifest = manifest;
        this.files = List.copyOf(files);
    }

    public SourceBundle.Manifest manifest() { return manifest; }

    /** File-table order, excluding the non-source JSON manifest itself. */
    public List<String> sourceNames() {
        var names = new ArrayList<String>();
        names.add(manifest.indexName());
        for (var part : manifest.parts()) names.add(part.fileName());
        return List.copyOf(names);
    }

    public void requireSourceNames(List<String> dwarfFiles) throws IOException {
        if (!sourceNames().equals(dwarfFiles)) {
            throw new IOException("DWARF source files differ from the selected source bundle");
        }
    }

    /** Index, manifest, then parts; all are required when retaining or transporting this export. */
    public List<Path> files() { return files.stream().map(File::path).toList(); }

    public void verify(BooleanSupplier cancelled) throws IOException {
        for (File file : files) {
            var expected = file.state();
            if (!expected.equals(SourceBundleStore.observe(file.path(), expected.size(), expected.sha256(), cancelled))) {
                throw new IOException("synthetic source bundle changed: " + file.path());
            }
        }
    }

    /** Ordinary single-file source returns empty; a recognized but incomplete bundle is an error. */
    public static Optional<SourceBundleFiles> open(Path index, BooleanSupplier cancelled) throws IOException {
        SourceBundle.check(cancelled);
        Path source = FileSystemPaths.resolveLeaf(index, "synthetic source index");
        if (!Files.isRegularFile(source, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("synthetic source must be a regular file: " + source);
        }
        try (var input = Files.newInputStream(source, LinkOption.NOFOLLOW_LINKS)) {
            if (!Arrays.equals(input.readNBytes(PREFIX.length), PREFIX)) return Optional.empty();
        }
        Bytes selected = read(source, MAX_INDEX, cancelled);
        String contents = new String(selected.bytes(), StandardCharsets.UTF_8);
        String[] beginning = contents.split("\n", 4);
        if (beginning.length != 4 || !beginning[2].matches(" \\* Manifest: forge-src-[0-9a-f]{64}\\.json")) {
            throw new IOException("invalid synthetic source index manifest reference");
        }
        String name = beginning[2].substring(" * Manifest: ".length());
        Path manifestPath = source.getParent().resolve(name);
        Bytes inventory = read(manifestPath, MAX_MANIFEST, cancelled);
        String manifestSha = inventory.file().state().sha256();
        if (!name.equals(SourceBundle.manifestNameFor(manifestSha))) {
            throw new IOException("source manifest differs from its content identity");
        }
        var manifest = SourceBundle.read(inventory.bytes(), cancelled);
        if (!manifest.indexName().equals(source.getFileName().toString()) ||
                !Arrays.equals(selected.bytes(), SourceBundle.renderIndex(manifest, manifestSha, cancelled))) {
            throw new IOException("synthetic source index differs from its manifest");
        }
        var files = new ArrayList<File>();
        files.add(selected.file());
        files.add(inventory.file());
        MessageDigest logical = digest();
        for (var part : manifest.parts()) {
            SourceBundle.check(cancelled);
            Path path = source.getParent().resolve(part.fileName());
            // Verification is bounded-memory even if an indivisible function is much larger than the line target.
            files.add(readPart(path, part, logical, cancelled));
        }
        if (!HexFormat.of().formatHex(logical.digest()).equals(manifest.logicalSourceSha256())) {
            throw new IOException("source parts do not reconstruct the recorded logical source");
        }
        var bundle = new SourceBundleFiles(manifest, files);
        bundle.verify(cancelled);
        return Optional.of(bundle);
    }

    private static File readPart(Path path, SourceBundle.Part part, MessageDigest logical,
            BooleanSupplier cancelled) throws IOException {
        byte[] header = SourcePartitionPlan.syntheticHeader();
        var before = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!before.isRegularFile() || before.size() != part.bytes()) {
            throw new IOException("source bundle is missing a complete regular part: " + path);
        }
        MessageDigest bytesDigest = digest();
        long bytes = 0;
        long lines = 0;
        int last = -1;
        byte[] buffer = new byte[65536];
        try (var input = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) {
            while (true) {
                SourceBundle.check(cancelled);
                int count = input.read(buffer);
                if (count < 0) break;
                if (count == 0 || bytes + count > part.bytes()) throw new IOException("source part size changed");
                bytesDigest.update(buffer, 0, count);
                int content = (int) Math.min(count, Math.max(0, header.length - bytes));
                for (int i = 0; i < content; i++) {
                    if (buffer[i] != header[(int) bytes + i]) throw new IOException("source part lacks synthetic header");
                }
                logical.update(buffer, content, count - content);
                for (int i = content; i < count; i++) if (buffer[i] == '\n') lines++;
                last = buffer[count - 1];
                bytes += count;
            }
        }
        var after = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (bytes != part.bytes() || bytes <= header.length || last != '\n' ||
                lines != (long) part.last() - part.first() + 1 ||
                !HexFormat.of().formatHex(bytesDigest.digest()).equals(part.sha256()) ||
                !after.isRegularFile() || before.size() != after.size() ||
                !java.util.Objects.equals(before.fileKey(), after.fileKey()) ||
                !before.lastModifiedTime().equals(after.lastModifiedTime())) {
            throw new IOException("source part contents or line bounds disagree with manifest: " + path);
        }
        return new File(path, new SourceBundleStore.State(after.fileKey(), after.size(), after.lastModifiedTime(), part.sha256()));
    }

    private static Bytes read(Path path, int maximum, BooleanSupplier cancelled) throws IOException {
        SourceBundle.check(cancelled);
        var before = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!before.isRegularFile() || before.size() > maximum) throw new IOException("invalid or oversized source inventory: " + path);
        var output = new ByteArrayOutputStream();
        byte[] buffer = new byte[65536];
        try (var input = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) {
            while (true) {
                SourceBundle.check(cancelled);
                int count = input.read(buffer);
                if (count < 0) break;
                if (count == 0 || (long) output.size() + count > before.size()) throw new IOException("source inventory size changed");
                output.write(buffer, 0, count);
            }
        }
        byte[] bytes = output.toByteArray();
        var state = SourceBundleStore.observe(path, bytes.length, SourceBundle.sha256(bytes), cancelled);
        if (state == null || before.size() != state.size() ||
                !java.util.Objects.equals(before.fileKey(), state.key()) || !before.lastModifiedTime().equals(state.modified())) {
            throw new IOException("source inventory changed during observation: " + path);
        }
        return new Bytes(bytes, new File(path, state));
    }

    private static MessageDigest digest() {
        try { return MessageDigest.getInstance("SHA-256"); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }
}
