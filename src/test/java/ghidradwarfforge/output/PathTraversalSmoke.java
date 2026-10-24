package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;

import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.nativeapi.PackagedNativeLibraries;
import ghidradwarfforge.source.SyntheticSourceFile;

/** Real filesystem traversal, leaf naming and non-destructive publication guards. */
public final class PathTraversalSmoke {
    private PathTraversalSmoke() {
    }

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("forge-path-traversal-").toRealPath();
        try {
            traversal(root.resolve("traversal"));
            aliases(root.resolve("aliases"));
            nonFileDestinations(root.resolve("non-files"));
            stageLinks(root.resolve("stage-links"));
            outputLinks(root.resolve("output-links"));
            System.out.println("path-traversal-smoke=PASS");
        }
        finally {
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                    Files.delete(path);
                }
            }
        }
    }

    private static void traversal(Path root) throws Exception {
        Path logical = Files.createDirectories(root.resolve("logical"));
        Path actual = Files.createDirectories(root.resolve("actual"));
        Path child = Files.createDirectory(actual.resolve("child"));
        Files.createSymbolicLink(logical.resolve("link"), child);
        Files.writeString(logical.resolve("input"), "lexical sentinel input");
        Files.writeString(actual.resolve("input"), "physical sentinel input");
        Path requestedInput = logical.resolve("link/../input");
        // Windows junction/symlink traversal need not have POSIX semantics.
        // Use the actual host's file lookup as the oracle, not a guessed parent.
        Path expectedInput = requestedInput.toRealPath();
        Path expectedParent = expectedInput.getParent();
        Path otherParent = expectedParent.equals(actual) ? logical : actual;
        var defaults = OutputPathPolicy.resolve(requestedInput, null);
        require(Files.isSameFile(defaults.input(), requestedInput), "input traversal changed");
        require(Arrays.equals(Files.readAllBytes(defaults.input()),
            Files.readAllBytes(requestedInput)), "input bytes disagree with requested traversal");
        require(defaults.artifact().equals(expectedParent.resolve("input.dbg")),
            "default output directory changed traversal");

        Path output = logical.resolve("link/../chosen name $literal.dbg");
        var explicit = OutputPathPolicy.resolve(requestedInput, output);
        require(explicit.artifact().equals(expectedParent.resolve(output.getFileName())),
            "explicit output directory changed traversal");
        Path lookalike = otherParent.resolve(output.getFileName());
        Files.writeString(lookalike, "untouched lexical lookalike");
        ArtifactPairPublisher.stageAndPublish(output, Path.of(output + ".c"),
            stage -> Files.writeString(stage, "artifact"),
            stage -> Files.writeString(stage, "source"), () -> { });
        text(explicit.artifact(), "artifact");
        text(explicit.source(), "source");
        text(lookalike, "untouched lexical lookalike");

        var source = new SyntheticSourceFile("standalone source".getBytes(
            java.nio.charset.StandardCharsets.UTF_8), List.of(), List.of());
        source.writeAtomically(logical.resolve("link/../standalone.c"));
        text(expectedParent.resolve("standalone.c"), "standalone source");
        require(!Files.exists(otherParent.resolve("standalone.c")),
            "standalone source was redirected");

        Path friendly = logical.resolve("friendly-name");
        Files.createSymbolicLink(friendly, actual.resolve("input"));
        var linked = OutputPathPolicy.resolve(friendly, null);
        require(linked.input().equals(friendly) &&
            linked.artifact().equals(logical.resolve("friendly-name.dbg")) &&
            linked.source().equals(logical.resolve("friendly-name.dbg.c")),
            "input leaf symlink changed the default basename or directory");
        reject(() -> OutputPathPolicy.resolve(friendly, actual.resolve("input")), "aliases");
        Path originalLink = logical.resolve("original-hard-link");
        Files.createLink(originalLink, actual.resolve("input"));
        reject(() -> OutputPathPolicy.resolve(friendly, originalLink), "aliases");
        Path sourceAlias = logical.resolve("source-alias.dbg.c");
        Files.createSymbolicLink(sourceAlias, actual.resolve("input"));
        reject(() -> OutputPathPolicy.resolve(friendly,
            logical.resolve("source-alias.dbg")), "aliases");
        text(actual.resolve("input"), "physical sentinel input");

        for (Path invalid : List.of(Path.of(""), Path.of("."), Path.of(".."),
                logical.resolve("."), logical.resolve(".."), root.getRoot())) {
            reject(() -> FileSystemPaths.resolveLeaf(invalid, "test path"), "must name a file");
        }
        reject(() -> OutputPathPolicy.resolve(requestedInput,
            root.resolve("missing/output")), "directory");
        require(!Files.exists(root.resolve("missing")), "missing parent was created");
        packagedLookup(logical.resolve("link/.."), expectedParent);
        standalonePreflight(logical.resolve("link/.."), expectedParent, otherParent);
        System.out.println("host-traversal-parent=" + expectedParent.getFileName());
    }

    private static void standalonePreflight(Path traversal, Path expected, Path other)
            throws Exception {
        byte[] invalidClass = new byte[16];
        invalidClass[0] = 0x7f;
        invalidClass[1] = 'E';
        invalidClass[2] = 'L';
        invalidClass[3] = 'F';
        invalidClass[4] = 3;
        Files.write(expected.resolve("standalone-input"), invalidClass);
        Files.write(other.resolve("standalone-input"), new byte[16]);
        Files.writeString(expected.resolve("consumer"), "not a native library");
        Files.writeString(expected.resolve("producer"), "not a native library");
        // These regular files satisfy preflight. The precise ELF diagnostic
        // proves the requested input was reached before any native loading.
        reject(() -> new MinimalDwarfSidecarExporter().export(
            traversal.resolve("standalone-input"), traversal.resolve("never-written.dbg"),
            traversal.resolve("consumer"), traversal.resolve("producer"),
            List.of(new FunctionSymbol("fixture", 0x1000, 4))), "unsupported ELF class 3");
        require(!Files.exists(expected.resolve("never-written.dbg")) &&
            !Files.exists(other.resolve("never-written.dbg")), "rejected export wrote output");
        require(Arrays.equals(invalidClass, Files.readAllBytes(expected.resolve("standalone-input"))),
            "standalone preflight modified input");
    }

    private static void packagedLookup(Path traversal, Path expected) throws Exception {
        Path directory = Files.createDirectories(expected.resolve("os/linux_x86_64"));
        Files.writeString(directory.resolve("libdwarf.so"), "consumer");
        Files.writeString(directory.resolve("libdwarfp.so"), "producer");
        Files.writeString(directory.resolve("NATIVE-PAIR.properties"),
            "consumer=libdwarf.so\nproducer=libdwarfp.so\n");
        StringBuilder manifest = new StringBuilder();
        for (String name : List.of("NATIVE-PAIR.properties", "libdwarf.so", "libdwarfp.so")) {
            manifest.append(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(Files.readAllBytes(directory.resolve(name)))))
                .append("  ").append(name).append('\n');
        }
        Files.writeString(directory.resolve("SHA256SUMS"), manifest);
        var pair = PackagedNativeLibraries.resolve(traversal, "linux_x86_64");
        require(pair.directory().equals(directory), "packaged native directory changed traversal");
        text(pair.consumer(), "consumer");
        text(pair.producer(), "producer");
    }

    private static void aliases(Path root) throws Exception {
        Files.createDirectories(root);
        for (int first = 0; first < 4; first++) {
            for (int second = first + 1; second < 4; second++) {
                for (String mode : List.of("direct", "parent-link", "hard-link")) {
                    Path directory = Files.createDirectory(root.resolve(first + "-" + second + "-" + mode));
                    Path[] files = files(directory);
                    Path[] selected = files.clone();
                    if (mode.equals("direct")) {
                        selected[second] = selected[first];
                    }
                    else if (mode.equals("parent-link")) {
                        Path alias = directory.resolve("parent-alias");
                        Files.createSymbolicLink(alias, directory);
                        selected[second] = alias.resolve(selected[first].getFileName());
                    }
                    else {
                        Files.delete(files[second]);
                        Files.createLink(files[second], files[first]);
                    }
                    byte[][] contents = contents(files);
                    FileTime[] times = times(files);
                    reject(() -> ArtifactPairPublisher.publish(selected[0], selected[1],
                        selected[2], selected[3]), "distinct");
                    unchanged(files, contents, times);
                }
            }
        }
        Path directory = Files.createDirectory(root.resolve("same-final-callbacks"));
        Path target = Files.writeString(directory.resolve("target"), "sentinel");
        reject(() -> ArtifactPairPublisher.stageAndPublish(target, target,
            stage -> { throw new AssertionError("artifact callback ran for aliased finals"); },
            stage -> { throw new AssertionError("source callback ran for aliased finals"); },
            () -> { }), "distinct");
        text(target, "sentinel");
        try (var entries = Files.list(directory)) {
            require(entries.count() == 1, "alias rejection created a temporary output");
        }
    }

    private static void stageLinks(Path root) throws Exception {
        Files.createDirectories(root);
        for (int stage : new int[] { 0, 2 }) {
            Path directory = Files.createDirectory(root.resolve("stage-" + stage));
            Path[] files = files(directory);
            Path referent = Files.writeString(directory.resolve("referent"), "unrelated bytes");
            FileTime time = Files.getLastModifiedTime(referent);
            Files.delete(files[stage]);
            Files.createSymbolicLink(files[stage], referent);
            reject(() -> ArtifactPairPublisher.publish(files[0], files[1], files[2], files[3]),
                "staged artifact is missing");
            require(Files.isSymbolicLink(files[stage]), "rejected staged link was removed");
            text(referent, "unrelated bytes");
            require(Files.getLastModifiedTime(referent).equals(time), "staged-link referent time changed");
            for (int index = 0; index < files.length; index++) {
                if (index != stage) {
                    text(files[index], "sentinel " + index);
                }
            }
        }
    }

    private static void nonFileDestinations(Path root) throws Exception {
        Files.createDirectories(root);
        for (int target : new int[] { 1, 3 }) {
            Path directory = Files.createDirectory(root.resolve("directory-" + target));
            Path[] files = files(directory);
            Files.delete(files[target]);
            Files.createDirectory(files[target]);
            Path child = Files.writeString(files[target].resolve("sentinel"), "directory contents");
            reject(() -> ArtifactPairPublisher.publish(files[0], files[1], files[2], files[3]),
                "destination must be a regular file or symbolic link");
            reject(() -> ArtifactPairPublisher.stageAndPublish(files[1], files[3],
                stage -> { throw new AssertionError("callback ran for a directory target"); },
                stage -> { throw new AssertionError("callback ran for a directory target"); },
                () -> { }), "destination must be a regular file or symbolic link");
            text(child, "directory contents");
            for (int index = 0; index < files.length; index++) {
                if (index != target) {
                    text(files[index], "sentinel " + index);
                }
            }
            try (var entries = Files.list(directory)) {
                require(entries.count() == 4, "directory rejection left temporary files");
            }
        }
        if (Files.getFileStore(root).supportsFileAttributeView("posix")) {
            Path directory = Files.createDirectory(root.resolve("fifo"));
            Path[] files = files(directory);
            Files.delete(files[1]);
            Process process = new ProcessBuilder("mkfifo", files[1].toString()).start();
            require(process.waitFor(10, java.util.concurrent.TimeUnit.SECONDS) &&
                process.exitValue() == 0, "cannot create POSIX FIFO control");
            require(Files.readAttributes(files[1], java.nio.file.attribute.BasicFileAttributes.class,
                LinkOption.NOFOLLOW_LINKS).isOther(), "FIFO control is not a special file");
            reject(() -> ArtifactPairPublisher.publish(files[0], files[1], files[2], files[3]),
                "destination must be a regular file or symbolic link");
            reject(() -> ArtifactPairPublisher.stageAndPublish(files[1], files[3],
                stage -> { throw new AssertionError("callback ran for FIFO target"); },
                stage -> { throw new AssertionError("callback ran for FIFO target"); },
                () -> { }), "destination must be a regular file or symbolic link");
            text(files[0], "sentinel 0");
            text(files[2], "sentinel 2");
            text(files[3], "sentinel 3");
            require(Files.readAttributes(files[1], java.nio.file.attribute.BasicFileAttributes.class,
                LinkOption.NOFOLLOW_LINKS).isOther(), "FIFO rejection replaced the special file");
            System.out.println("posix-fifo-destination-rejection=PASS");
        }
        Path referent = Files.createDirectory(root.resolve("directory-referent"));
        Path sentinel = Files.writeString(referent.resolve("sentinel"), "unrelated directory");
        Path artifact = root.resolve("directory-link.dbg");
        Files.createSymbolicLink(artifact, referent);
        ArtifactPairPublisher.stageAndPublish(artifact, Path.of(artifact + ".c"),
            stage -> Files.writeString(stage, "artifact"),
            stage -> Files.writeString(stage, "source"), () -> { });
        text(artifact, "artifact");
        text(sentinel, "unrelated directory");
    }

    private static void outputLinks(Path root) throws Exception {
        Files.createDirectories(root);
        for (boolean dangling : new boolean[] { false, true }) {
            Path directory = Files.createDirectory(root.resolve("dangling-" + dangling));
            Path[] files = files(directory);
            Path originalArtifact = directory.resolve("old-artifact");
            Path originalSource = directory.resolve("old-source");
            if (!dangling) {
                Files.writeString(originalArtifact, "untouched artifact referent");
                Files.writeString(originalSource, "untouched source referent");
            }
            Files.delete(files[1]);
            Files.delete(files[3]);
            Files.createSymbolicLink(files[1], originalArtifact);
            Files.createSymbolicLink(files[3], originalSource);
            // Deleting the owned source stage after the first install forces
            // failure after the old source link has also moved into its backup.
            try {
                ArtifactPairPublisher.publish(files[0], files[1], files[2], files[3],
                    () -> Files.delete(files[2]));
                throw new AssertionError("controlled missing source stage was ignored");
            }
            catch (IOException expected) {
                require(Files.isSymbolicLink(files[1]) && Files.isSymbolicLink(files[3]),
                    "rollback lost an original output link");
                require(Files.readSymbolicLink(files[1]).equals(originalArtifact) &&
                    Files.readSymbolicLink(files[3]).equals(originalSource), "rollback changed link text");
            }
            if (!dangling) {
                text(originalArtifact, "untouched artifact referent");
                text(originalSource, "untouched source referent");
            }
            else {
                require(!Files.exists(originalArtifact, LinkOption.NOFOLLOW_LINKS) &&
                    !Files.exists(originalSource, LinkOption.NOFOLLOW_LINKS), "dangling referent created");
            }
            Files.writeString(files[0], "new artifact");
            Files.writeString(files[2], "new source");
            ArtifactPairPublisher.publish(files[0], files[1], files[2], files[3]);
            require(!Files.isSymbolicLink(files[1]) && !Files.isSymbolicLink(files[3]),
                "publication followed output leaf links");
            text(files[1], "new artifact");
            text(files[3], "new source");
            if (!dangling) {
                text(originalArtifact, "untouched artifact referent");
                text(originalSource, "untouched source referent");
            }
        }
    }

    private static Path[] files(Path directory) throws IOException {
        Path[] result = new Path[4];
        for (int index = 0; index < result.length; index++) {
            result[index] = Files.writeString(directory.resolve("file-" + index), "sentinel " + index);
        }
        return result;
    }

    private static byte[][] contents(Path[] files) throws IOException {
        byte[][] result = new byte[files.length][];
        for (int index = 0; index < files.length; index++) {
            result[index] = Files.readAllBytes(files[index]);
        }
        return result;
    }

    private static FileTime[] times(Path[] files) throws IOException {
        FileTime[] result = new FileTime[files.length];
        for (int index = 0; index < files.length; index++) {
            result[index] = Files.getLastModifiedTime(files[index]);
        }
        return result;
    }

    private static void unchanged(Path[] files, byte[][] contents, FileTime[] times)
            throws IOException {
        for (int index = 0; index < files.length; index++) {
            require(Arrays.equals(contents[index], Files.readAllBytes(files[index])) &&
                times[index].equals(Files.getLastModifiedTime(files[index])),
                "alias rejection modified or removed a caller file");
        }
    }

    private static void text(Path file, String expected) throws IOException {
        require(Files.readString(file).equals(expected), "unexpected bytes in " + file);
    }

    private static void reject(Action action, String message) throws Exception {
        try {
            action.run();
            throw new AssertionError("expected rejection containing " + message);
        }
        catch (IOException | IllegalArgumentException expected) {
            require(expected.getMessage().contains(message), "unexpected rejection: " + expected);
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    @FunctionalInterface
    private interface Action {
        void run() throws Exception;
    }
}
