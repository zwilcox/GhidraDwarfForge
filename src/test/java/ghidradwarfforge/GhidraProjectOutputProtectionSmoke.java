package ghidradwarfforge;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.ProjectLocator;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** Real filesystem aliases; only Program/DomainFile association is stubbed. */
public final class GhidraProjectOutputProtectionSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        Path root = Files.createTempDirectory("forge-project-protection-");
        try {
            exercise(root);
        }
        finally {
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
        System.out.println("project-output-protection=PASS checks=" + checks);
    }

    private static void exercise(Path root) throws Exception {
        var locator = new ProjectLocator(root.toString(), "saved");
        Path project = Files.createDirectories(locator.getProjectDir().toPath());
        Path marker = Files.writeString(locator.getMarkerFile().toPath(), "original marker");
        Path lock = Files.writeString(locator.getProjectLockFile().toPath(), "original lock");
        Path nested = Files.createDirectory(project.resolve("nested"));
        Path data = Files.writeString(nested.resolve("database"), "curated analyst data");
        Path outside = Files.createDirectory(root.resolve("outside"));
        Path original = Files.writeString(outside.resolve("original"), "original executable");
        Path similar = Files.createDirectory(root.resolve("saved.rep-sibling"));
        Path newOutput = outside.resolve("new.dbg");
        Program program = program(domain(locator));

        // Unsaved/detached objects have no project to protect. No output is created.
        allow(root, program(null), List.of(newOutput));
        allow(root, program(domain(null)), List.of(newOutput));
        allow(root, program, List.of());
        allow(root, program, List.of(original, newOutput, similar.resolve("new.dbg")));
        refuse(root, program, project.resolve("new.dbg"), "inside the saved project");
        refuse(root, program, data, "inside the saved project");
        refuse(root, program, nested.resolve("../new.dbg"), "inside the saved project");
        refuse(root, program, marker, "aliases a saved project file");
        refuse(root, program, lock, "aliases a saved project file");
        refuse(root, program, outside.resolve("missing/new.dbg"), "parent directory is missing");

        Path parentLink = Files.createSymbolicLink(outside.resolve("project-link"), project);
        refuse(root, program, parentLink.resolve("new.dbg"), "inside the saved project");
        for (Path protectedFile : List.of(marker, lock, data)) {
            Path hard = outside.resolve(protectedFile.getFileName() + ".hard");
            Path symbolic = outside.resolve(protectedFile.getFileName() + ".symlink");
            Files.createLink(hard, protectedFile);
            Files.createSymbolicLink(symbolic, protectedFile);
            refuse(root, program, hard, "aliases a saved project file");
            refuse(root, program, symbolic, "aliases a saved project file");
        }

        // A directory symlink must not cause a walk outside the saved project.
        Files.createSymbolicLink(project.resolve("directory-link"), outside);
        Files.createSymbolicLink(project.resolve("cycle"), project);
        allow(root, program, List.of(original, newOutput));
        // A *file* symlink inside the project still protects its target identity.
        Files.createSymbolicLink(project.resolve("referenced-file"), original);
        refuse(root, program, original, "aliases a saved project file");

        var counter = new CountingMonitor(Integer.MAX_VALUE);
        Path unrelated = Files.writeString(outside.resolve("unrelated"), "external file");
        Map<String, String> before = snapshot(root);
        GhidraProjectOutputProtection.requireSafeOutputs(program, List.of(newOutput), counter);
        if (counter.calls != 1) throw new AssertionError("fresh output traversed the saved project");
        counter = new CountingMonitor(Integer.MAX_VALUE);
        GhidraProjectOutputProtection.requireSafeOutputs(program, List.of(unrelated), counter);
        try (var entries = Files.walk(project)) {
            if (counter.calls != 1 + entries.count()) throw new AssertionError("project traversal skipped a cancellation check");
        }
        for (int index = 1; index <= counter.calls; index++) {
            var cancelled = new CountingMonitor(index);
            try {
                GhidraProjectOutputProtection.requireSafeOutputs(program, List.of(unrelated), cancelled);
                throw new AssertionError("ignored cancellation at checkpoint " + index);
            }
            catch (CancelledException expected) {
                if (cancelled.calls != index) throw new AssertionError("late cancellation");
            }
            unchanged(root, before);
            checks++;
        }

        // Even absent marker/lock names remain reserved for the project.
        Files.delete(outside.resolve(marker.getFileName() + ".hard"));
        Files.delete(outside.resolve(lock.getFileName() + ".hard"));
        Files.delete(marker);
        Files.delete(lock);
        refuse(root, program, marker, "aliases a saved project file");
        refuse(root, program, lock, "aliases a saved project file");
        var absent = new ProjectLocator(root.toString(), "absent");
        before = snapshot(root);
        try {
            GhidraProjectOutputProtection.requireSafeOutputs(program(domain(absent)),
                List.of(newOutput), TaskMonitor.DUMMY);
            throw new AssertionError("accepted missing saved project directory");
        }
        catch (java.nio.file.NoSuchFileException expected) { checks++; }
        unchanged(root, before);
    }

    private static void allow(Path root, Program program, List<Path> outputs) throws Exception {
        var before = snapshot(root);
        GhidraProjectOutputProtection.requireSafeOutputs(program, outputs, TaskMonitor.DUMMY);
        unchanged(root, before);
        checks++;
    }

    private static void refuse(Path root, Program program, Path output, String diagnostic) throws Exception {
        var before = snapshot(root);
        try {
            GhidraProjectOutputProtection.requireSafeOutputs(program, List.of(output), TaskMonitor.DUMMY);
            throw new AssertionError("accepted protected output " + output);
        }
        catch (IOException expected) {
            if (!expected.getMessage().contains(diagnostic)) throw new AssertionError("wrong refusal", expected);
        }
        unchanged(root, before);
        checks++;
    }

    private static Map<String, String> snapshot(Path root) throws IOException {
        var entries = new TreeMap<String, String>();
        try (var paths = Files.walk(root)) {
            for (Path path : paths.toList()) {
                String value;
                if (Files.isSymbolicLink(path)) value = "link:" + Files.readSymbolicLink(path);
                else if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) value = "directory";
                else value = "file:" + Files.readAttributes(path, java.nio.file.attribute.BasicFileAttributes.class)
                    .fileKey() + ":" + Base64.getEncoder().encodeToString(Files.readAllBytes(path));
                entries.put(root.relativize(path).toString(), value);
            }
        }
        return entries;
    }

    private static void unchanged(Path root, Map<String, String> before) throws IOException {
        if (!before.equals(snapshot(root))) throw new AssertionError("protection mutated files or links");
    }

    private static Program program(DomainFile file) {
        return stub(Program.class, "getDomainFile", file);
    }

    private static DomainFile domain(ProjectLocator locator) {
        return stub(DomainFile.class, "getProjectLocator", locator);
    }

    private static <T> T stub(Class<T> type, String accessor, Object value) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type},
            (proxy, method, arguments) -> {
                if (method.getName().equals(accessor)) return value;
                throw new AssertionError("unexpected project access: " + method);
            }));
    }

    private static final class CountingMonitor extends TaskMonitorAdapter {
        private final int stopAt;
        private int calls;

        CountingMonitor(int stopAt) { this.stopAt = stopAt; }

        @Override
        public void checkCancelled() throws CancelledException {
            if (++calls == stopAt) throw new CancelledException();
        }
    }
}
