package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** Resolves existing directory traversal while preserving the chosen file leaf. */
public final class FileSystemPaths {
    private FileSystemPaths() {
    }

    /**
     * Resolves the parent before removing any dot components. Following the leaf
     * would change default names for input links and replacement semantics for
     * output links, so the returned path retains that directory entry.
     */
    public static Path resolveLeaf(Path path, String description) throws IOException {
        if (path == null) {
            throw new IllegalArgumentException(description + " is required");
        }
        Path leaf = path.getFileName();
        if (leaf == null || leaf.toString().isEmpty() || leaf.toString().equals(".") ||
                leaf.toString().equals("..")) {
            throw new IOException(description + " must name a file, not a directory component");
        }
        Path absolute = path.toAbsolutePath();
        Path parent = absolute.getParent();
        if (parent == null || !Files.isDirectory(parent)) {
            throw new IOException(description + " parent directory is missing or not a directory: " +
                parent);
        }
        return parent.toRealPath().resolve(leaf);
    }

    /** Paths must already have resolved parents; existing leaf identity follows links. */
    static boolean aliases(Path first, Path second) throws IOException {
        return first.equals(second) || (Files.exists(first) && Files.exists(second) &&
            Files.isSameFile(first, second));
    }
}
