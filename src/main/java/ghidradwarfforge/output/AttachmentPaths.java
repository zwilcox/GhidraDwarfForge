package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Read-only, all-role path preflight for the attachment transaction. Includes
 * receipts, retained generations, backups, validation inputs and optional logs.
 * No destination is opened for writing, including when preflight fails.
 *
 * This checks paths and available provider keys/size/mtime, not file content,
 * native identity/link count, validation approval or a race-free snapshot. The
 * transaction must additionally use its host adapter and digest-bound receipts.
 */
public final class AttachmentPaths {
    public enum Kind { TARGET, INPUT, NEW_FILE }

    public record Selection(String role, Path path, Kind kind) {
        public Selection {
            if (role == null || !role.matches("[a-z][a-zA-Z0-9]{0,63}")) {
                throw new IllegalArgumentException("invalid attachment path role");
            }
            Objects.requireNonNull(path, "path");
            Objects.requireNonNull(kind, "kind");
        }
    }

    private record Observed(Selection selection, Object identity, long size,
            java.nio.file.attribute.FileTime modified) {
    }

    public static final class Plan {
        private final List<Observed> observations;
        private final Map<String, Path> paths;

        private Plan(List<Observed> observations) {
            this.observations = List.copyOf(observations);
            Map<String, Path> result = new LinkedHashMap<>();
            for (Observed observed : observations) {
                result.put(observed.selection().role(), observed.selection().path());
            }
            paths = Map.copyOf(result);
        }

        public Map<String, Path> paths() {
            return paths;
        }

        /** Call before creating any output, after slow validation or user interaction. */
        public void recheck() throws IOException {
            for (Observed expected : observations) {
                if (!FileSystemPaths.resolveLeaf(expected.selection().path(), expected.selection().role())
                        .equals(expected.selection().path())) {
                    throw new IOException("attachment parent traversal changed: " + expected.selection().role());
                }
                Observed current = observe(expected.selection());
                if (!Objects.equals(expected.identity(), current.identity()) ||
                        expected.size() != current.size() ||
                        !Objects.equals(expected.modified(), current.modified())) {
                    throw new IOException("attachment selection changed: " + expected.selection().role());
                }
            }
            rejectAliases(observations);
        }
    }

    private AttachmentPaths() {
    }

    public static Plan preflight(List<Selection> selections) throws IOException {
        if (selections == null || selections.isEmpty() || selections.size() > 128) {
            throw new IllegalArgumentException("attachment requires 1..128 selected paths");
        }
        Map<String, Selection> roles = new LinkedHashMap<>();
        List<Observed> observed = new ArrayList<>();
        for (Selection selected : selections) {
            Objects.requireNonNull(selected, "selection");
            if (roles.putIfAbsent(selected.role(), selected) != null) {
                throw new IOException("duplicate attachment path role: " + selected.role());
            }
            Path resolved = FileSystemPaths.resolveLeaf(selected.path(), selected.role());
            observed.add(observe(new Selection(selected.role(), resolved, selected.kind())));
        }
        rejectAliases(observed);
        return new Plan(observed);
    }

    private static Observed observe(Selection selected) throws IOException {
        BasicFileAttributes leaf;
        try {
            leaf = Files.readAttributes(selected.path(), BasicFileAttributes.class,
                LinkOption.NOFOLLOW_LINKS);
        }
        catch (NoSuchFileException missing) {
            if (selected.kind() == Kind.NEW_FILE) {
                return new Observed(selected, null, 0, null);
            }
            throw missing;
        }
        if (selected.kind() == Kind.NEW_FILE) {
            throw new IOException("new attachment destination already exists: " + selected.role());
        }
        if (selected.kind() == Kind.TARGET && !leaf.isRegularFile()) {
            throw new IOException("attachment target must be a regular non-link leaf: " + selected.role());
        }
        BasicFileAttributes actual = Files.readAttributes(selected.path(), BasicFileAttributes.class);
        if (!actual.isRegularFile()) {
            throw new IOException("attachment input must be a regular file: " + selected.role());
        }
        return new Observed(selected, actual.fileKey(), actual.size(), actual.lastModifiedTime());
    }

    private static void rejectAliases(List<Observed> observed) throws IOException {
        for (int first = 0; first < observed.size(); first++) {
            for (int second = first + 1; second < observed.size(); second++) {
                Observed a = observed.get(first);
                Observed b = observed.get(second);
                if (a.selection().path().equals(b.selection().path()) ||
                        (a.selection().kind() != Kind.NEW_FILE && b.selection().kind() != Kind.NEW_FILE &&
                            Files.isSameFile(a.selection().path(), b.selection().path()))) {
                    throw new IOException("attachment paths alias: " + a.selection().role() +
                        " and " + b.selection().role());
                }
            }
        }
    }
}
