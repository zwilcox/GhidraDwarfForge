package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/** Real directory-entry changes between read-only preflight and publication. */
public final class AttachmentPathBoundarySmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("forge-attachment-path-boundaries-");
        try { exercise(root); }
        finally {
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
    }

    static void exercise(Path root) throws Exception {
        for (String role : new String[] {null, "", "A", "a-b", "a".repeat(65), "a\0"}) {
            argument(() -> selection(role, root.resolve("unused"), AttachmentPaths.Kind.NEW_FILE));
        }
        argument(() -> AttachmentPaths.preflight(null));
        argument(() -> AttachmentPaths.preflight(List.of()));
        Path selectionParent = Files.createDirectory(root.resolve("selected-parent"));
        Path canonicalParent = selectionParent.toRealPath();
        Path selectionAlias = Files.createSymbolicLink(root.resolve("selected-alias"), canonicalParent);
        var selections = new ArrayList<AttachmentPaths.Selection>();
        var canonicalSelections = new ArrayList<AttachmentPaths.Selection>();
        for (int i = 0; i < 128; i++) {
            String role = i == 0 ? "a".repeat(64) : "file" + i;
            selections.add(selection(role, selectionAlias.resolve("absent" + i), AttachmentPaths.Kind.NEW_FILE));
            canonicalSelections.add(selection(role, canonicalParent.resolve("absent" + i), AttachmentPaths.Kind.NEW_FILE));
        }
        AttachmentPaths.Plan boundary;
        try { boundary = AttachmentPaths.preflight(selections); }
        catch (IllegalArgumentException invalid) { throw new AssertionError("valid 128-path plan refused", invalid); }
        boundary.recheck();
        equal(128, boundary.paths().size());
        equal(canonicalSelections, boundary.selections());
        for (var selected : canonicalSelections) equal(selected.path(), boundary.paths().get(selected.role()));
        selections.clear();
        equal(128, boundary.selections().size());
        try { boundary.paths().clear(); throw new AssertionError("mutable path map"); }
        catch (UnsupportedOperationException expected) { checks++; }
        try { boundary.selections().clear(); throw new AssertionError("mutable selections"); }
        catch (UnsupportedOperationException expected) { checks++; }
        selections.addAll(boundary.selections());
        selections.add(selection("extra", root.resolve("absentExtra"), AttachmentPaths.Kind.NEW_FILE));
        argument(() -> AttachmentPaths.preflight(selections));
        io(() -> AttachmentPaths.preflight(List.of(boundary.selections().getFirst(),
            selection("a".repeat(64), root.resolve("other"), AttachmentPaths.Kind.NEW_FILE))));
        for (var selected : selections) {
            equal(false, Files.exists(selected.path(), LinkOption.NOFOLLOW_LINKS));
        }
        Path input = Files.writeString(root.resolve("input"), "original");
        Path absent = root.resolve("newOutput");
        // Both kind orders must accept distinct input/new output paths.
        var first = selection("input", input, AttachmentPaths.Kind.INPUT);
        var second = selection("output", absent, AttachmentPaths.Kind.NEW_FILE);
        AttachmentPaths.preflight(List.of(first, second)).recheck();
        AttachmentPaths.preflight(List.of(second, first)).recheck();
        io(() -> AttachmentPaths.preflight(List.of(selection("directory", root, AttachmentPaths.Kind.INPUT))));
        io(() -> AttachmentPaths.preflight(List.of(selection("missing", absent, AttachmentPaths.Kind.INPUT))));

        FileTime originalTime = Files.getLastModifiedTime(input);
        var sizePlan = AttachmentPaths.preflight(List.of(first, second));
        Files.writeString(input, "longer concurrent input");
        Files.setLastModifiedTime(input, originalTime);
        io(sizePlan::recheck);
        equal("longer concurrent input", Files.readString(input));
        Files.writeString(input, "original");
        Files.setLastModifiedTime(input, originalTime);
        var timePlan = AttachmentPaths.preflight(List.of(first, second));
        Files.setLastModifiedTime(input, FileTime.fromMillis(originalTime.toMillis() + 60_000));
        io(timePlan::recheck);
        equal("original", Files.readString(input));

        // A retained old entry prevents identity reuse. The portable preflight
        // compares provider keys only when the filesystem supplies them.
        // WindowsAttachmentHostSmoke separately proves native identity refusal.
        Files.setLastModifiedTime(input, originalTime);
        Object originalKey = Files.readAttributes(input, BasicFileAttributes.class).fileKey();
        var identityPlan = AttachmentPaths.preflight(List.of(first, second));
        Path retained = Files.move(input, root.resolve("retained"));
        Files.writeString(input, "original");
        Files.setLastModifiedTime(input, originalTime);
        Object replacementKey = Files.readAttributes(input, BasicFileAttributes.class).fileKey();
        if (originalKey == null && replacementKey == null) {
            identityPlan.recheck();
        }
        else {
            equal(false, java.util.Objects.equals(originalKey, replacementKey));
            io(identityPlan::recheck);
        }
        equal("original", Files.readString(retained));
        equal("original", Files.readString(input));
        equal(false, Files.exists(absent, LinkOption.NOFOLLOW_LINKS));

        Path directory = Files.createDirectory(root.resolve("directory"));
        Path file = Files.writeString(directory.resolve("file"), "retained parent input");
        var traversal = AttachmentPaths.preflight(List.of(selection("input", file, AttachmentPaths.Kind.INPUT)));
        Path saved = Files.move(directory, root.resolve("savedDirectory"));
        Path alternate = Files.createDirectory(root.resolve("alternate"));
        // Same leaf inode and metadata isolates the changed parent traversal.
        Files.createLink(alternate.resolve("file"), saved.resolve("file"));
        Files.createSymbolicLink(directory, alternate);
        io(traversal::recheck);
        equal("retained parent input", Files.readString(saved.resolve("file")));
        equal("retained parent input", Files.readString(alternate.resolve("file")));
        Files.delete(directory);
        Files.move(saved, directory);
        traversal.recheck();
        checks++;
        System.out.println("attachment-path-boundaries=PASS checks=" + checks);
    }

    private static AttachmentPaths.Selection selection(String role, Path path, AttachmentPaths.Kind kind) {
        return new AttachmentPaths.Selection(role, path, kind);
    }

    @FunctionalInterface private interface Action { void run() throws Exception; }

    private static void argument(Action action) throws Exception {
        try { action.run(); throw new AssertionError("invalid attachment path arguments accepted"); }
        catch (IllegalArgumentException expected) { checks++; }
    }

    private static void io(Action action) throws Exception {
        try { action.run(); throw new AssertionError("changed or ambiguous attachment paths accepted"); }
        catch (IOException expected) { checks++; }
    }

    private static void equal(Object expected, Object actual) {
        if (!expected.equals(actual)) throw new AssertionError(expected + " != " + actual);
        checks++;
    }
}
