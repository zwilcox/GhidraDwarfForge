package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;
import java.util.function.Predicate;

/** Resolves and validates the original ELF and its sidecar/source destinations. */
public final class OutputPathPolicy {
    public record ExportPaths(Path input, Path artifact, Path source,
            boolean defaultOutput) {
        public ExportPaths {
            Objects.requireNonNull(input, "input");
            Objects.requireNonNull(artifact, "artifact");
            Objects.requireNonNull(source, "source");
        }
    }

    private OutputPathPolicy() {
    }

    public static ExportPaths resolve(Path input, Path explicitOutput) throws IOException {
        return resolve(input, explicitOutput, Files::isWritable);
    }

    static ExportPaths resolve(Path input, Path explicitOutput,
            Predicate<Path> writableDirectory) throws IOException {
        Objects.requireNonNull(writableDirectory, "writableDirectory");
        Path original = normalize(input, "original ELF path");
        if (!Files.isRegularFile(original) || !Files.isReadable(original)) {
            throw new IOException("original ELF is missing, unreadable, or not a regular file: " +
                original + "; supply --input=<path> when Ghidra's executable path is stale");
        }
        if (original.getFileName() == null) {
            throw new IOException("original ELF has no usable filename: " + original);
        }

        boolean useDefault = explicitOutput == null;
        Path artifact = useDefault
                ? original.resolveSibling(original.getFileName() + ".dbg")
                : normalize(explicitOutput, "DWARF sidecar path");
        Path source = Path.of(artifact + ".c").toAbsolutePath().normalize();
        validateDestination(original, artifact, "DWARF sidecar", writableDirectory);
        validateDestination(original, source, "synthetic source", writableDirectory);
        if (!artifact.getParent().equals(source.getParent())) {
            throw new IOException("sidecar and synthetic source must share an output directory");
        }
        return new ExportPaths(original, artifact, source, useDefault);
    }

    private static void validateDestination(Path input, Path destination, String description,
            Predicate<Path> writableDirectory) throws IOException {
        if (destination.equals(input) ||
                (Files.exists(destination) && Files.isSameFile(destination, input))) {
            throw new IOException(description + " path aliases the original ELF: " + destination);
        }
        Path parent = destination.getParent();
        if (parent == null || !Files.isDirectory(parent) ||
                !writableDirectory.test(parent)) {
            throw new IOException(description + " directory is missing or not writable: " + parent);
        }
        if (Files.exists(destination) &&
                (!Files.isRegularFile(destination) || !Files.isWritable(destination))) {
            throw new IOException(description + " cannot replace existing path: " + destination);
        }
    }

    private static Path normalize(Path path, String description) {
        if (path == null) {
            throw new IllegalArgumentException(description + " is required");
        }
        return path.toAbsolutePath().normalize();
    }
}
