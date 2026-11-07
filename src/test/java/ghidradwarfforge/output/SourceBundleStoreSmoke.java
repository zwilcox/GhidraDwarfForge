package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

/** Failure/race tests prove that an installed inventory never refers to our partial source writes. */
public final class SourceBundleStoreSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("forge-source-store-");
        var plan = SourceBundle.prepare("a".repeat(64), "target.dbg.c", SourceBundleSmoke.fixture(), 3, () -> false);
        try {
            Path success = Files.createDirectory(root.resolve("success"));
            Path index = success.resolve("target.dbg.c");
            var installed = SourceBundleStore.install(index, plan, List.of(), () -> false);
            verifyInventory(success, plan);
            require(!Files.exists(index), "store must not publish mutable index before sidecar");
            var keys = installed.files().stream().map(path -> {
                try { return Files.readAttributes(path, java.nio.file.attribute.BasicFileAttributes.class).fileKey(); }
                catch (IOException error) { throw new RuntimeException(error); }
            }).toList();
            SourceBundleStore.install(index, plan, List.of(), () -> false).verify(() -> false);
            for (int i = 0; i < keys.size(); i++) {
                Object after = Files.readAttributes(installed.files().get(i), java.nio.file.attribute.BasicFileAttributes.class).fileKey();
                require(java.util.Objects.equals(keys.get(i), after), "identical reuse preserves inode");
            }
            Path first = installed.files().getFirst();
            FileTime future = FileTime.fromMillis(System.currentTimeMillis() + 60000);
            Files.setLastModifiedTime(first, future);
            reject(() -> installed.verify(() -> false));
            var reused = SourceBundleStore.install(index, plan, List.of(), () -> false);
            Path sidecar = Files.writeString(success.resolve("staged-sidecar"), "sidecar");
            reused.synchronizeSidecarTime(sidecar, () -> false);
            require(Files.getLastModifiedTime(sidecar).compareTo(future) >= 0, "source freshness on reused files");

            for (int stop = 0; stop < plan.fileNames().size(); stop++) {
                Path directory = Files.createDirectory(root.resolve("failure-" + stop));
                int failureAt = stop;
                reject(() -> SourceBundleStore.install(directory.resolve("target.dbg.c"), plan, List.of(), () -> false,
                    (number, target) -> { if (number == failureAt) throw new IOException("injected installation failure"); }));
                verifyInventory(directory, plan);
                require(!Files.exists(directory.resolve("target.dbg.c")), "failure never publishes index");
                // Complete retained files can be reused safely on retry.
                SourceBundleStore.install(directory.resolve("target.dbg.c"), plan, List.of(), () -> false).verify(() -> false);
                verifyInventory(directory, plan);
            }

            conflicts(root, plan);
            concurrentCreation(root, plan, true);
            concurrentCreation(root, plan, false);
            exclusiveLinkRace(root, plan, true);
            exclusiveLinkRace(root, plan, false);
            rollback(root, plan);
            cancellation(root, plan);
            System.out.println("source-bundle-store-smoke: PASS checks=" + checks);
        }
        finally {
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
    }

    private static void conflicts(Path root, SourceBundle.Plan plan) throws Exception {
        for (String kind : List.of("content", "directory", "hardlink", "path", "symlink", "dangling")) {
            if ((kind.equals("symlink") || kind.equals("dangling")) && !System.getProperty("os.name").equals("Linux")) continue;
            Path directory = Files.createDirectory(root.resolve(kind));
            String name = plan.fileNames().getLast();
            Path target = directory.resolve(name);
            Path protectedFile = Files.write(directory.resolve("original"), plan.bytes(name));
            switch (kind) {
                case "content" -> Files.writeString(target, "user content");
                case "directory" -> Files.createDirectory(target);
                case "hardlink" -> Files.createLink(target, protectedFile);
                case "path" -> { }
                case "symlink" -> Files.createSymbolicLink(target, protectedFile);
                case "dangling" -> Files.createSymbolicLink(target, directory.resolve("absent"));
                default -> throw new AssertionError(kind);
            }
            List<Path> protectedPaths = List.of(kind.equals("path") ? target : protectedFile);
            reject(() -> SourceBundleStore.install(directory.resolve("target.dbg.c"), plan, protectedPaths, () -> false));
            require(Arrays.equals(Files.readAllBytes(protectedFile), plan.bytes(name)), "protected bytes preserved");
            require(!Files.exists(directory.resolve(plan.fileNames().getFirst())), "all destinations preflight before any write");
            if (kind.equals("content")) require(Files.readString(target).equals("user content"), "conflicting user content preserved");
        }
        Path directory = Files.createDirectory(root.resolve("alias-after-install"));
        Path log = directory.resolve("log");
        var installed = SourceBundleStore.install(directory.resolve("target.dbg.c"), plan, List.of(log), () -> false);
        Files.createLink(log, installed.files().getFirst());
        reject(() -> installed.verify(() -> false));
        Files.delete(log);
        Path removed = installed.files().getLast();
        Files.delete(removed);
        reject(() -> installed.verify(() -> false));
    }

    private static void concurrentCreation(Path root, SourceBundle.Plan plan, boolean identical) throws Exception {
        Path directory = Files.createDirectory(root.resolve("concurrent-" + identical));
        Path next = directory.resolve(plan.fileNames().get(1));
        Operation operation = () -> SourceBundleStore.install(directory.resolve("target.dbg.c"), plan, List.of(), () -> false,
            (number, target) -> {
                if (number == 0) Files.write(next, identical ? plan.bytes(next.getFileName().toString()) : new byte[] { 1 });
            });
        if (identical) {
            operation.run();
            verifyInventory(directory, plan);
        }
        else {
            reject(operation);
            require(Arrays.equals(Files.readAllBytes(next), new byte[] { 1 }), "competing content not overwritten");
            require(!Files.exists(directory.resolve(plan.manifestName())), "manifest withheld after race");
        }
        Path changedDirectory = Files.createDirectory(root.resolve("changed-part-" + identical));
        reject(() -> SourceBundleStore.install(changedDirectory.resolve("target.dbg.c"), plan, List.of(), () -> false,
            (number, target) -> {
                if (number == plan.manifest().parts().size() - 1) {
                    Files.writeString(changedDirectory.resolve(plan.fileNames().getFirst()), "changed while installing");
                }
            }));
        require(!Files.exists(changedDirectory.resolve(plan.manifestName())), "recheck referenced files before manifest");
    }

    private static void rollback(Path root, SourceBundle.Plan plan) throws Exception {
        for (int stop = 0; stop < 3; stop++) {
            Path directory = Files.createDirectory(root.resolve("rollback-" + stop));
            Path original = Files.writeString(directory.resolve("original"), "original");
            Path sidecar = Files.writeString(directory.resolve("target.dbg"), "old sidecar");
            Path index = Files.writeString(directory.resolve("target.dbg.c"), "old index");
            Path companion = Files.writeString(directory.resolve("target.dbg.gdb.py"), "old loader");
            Path user = Files.writeString(directory.resolve("forge-src-user.c"), "analyst source");
            var oldPlan = SourceBundle.prepare("a".repeat(64), "target.dbg.c", SourceBundleSmoke.fixture(), 200, () -> false);
            var old = SourceBundleStore.install(index, oldPlan, List.of(original, sidecar, companion), () -> false);
            int failAfter = stop;
            reject(() -> CompanionArtifactPublisher.stageAndPublish(original, List.of(sidecar, index, companion), stages -> {
                var installed = SourceBundleStore.install(index, plan, List.of(original, sidecar, companion), () -> false);
                Files.writeString(stages.get(0), "new sidecar");
                Files.write(stages.get(1), plan.indexBytes(() -> false));
                Files.writeString(stages.get(2), "new loader");
                installed.synchronizeSidecarTime(stages.get(0), () -> false);
            }, () -> { }, installed -> { if (installed == failAfter) throw new IOException("pair publication failed"); }));
            require(Files.readString(sidecar).equals("old sidecar") && Files.readString(index).equals("old index") &&
                Files.readString(companion).equals("old loader"), "mutable generation rollback");
            require(Files.readString(original).equals("original") && Files.readString(user).equals("analyst source"), "user/input preservation");
            old.verify(() -> false);
            verifyInventory(directory, plan);
        }
    }

    private static void exclusiveLinkRace(Path root, SourceBundle.Plan plan, boolean identical) throws Exception {
        Path directory = Files.createDirectory(root.resolve("exclusive-race-" + identical));
        Path raced = directory.resolve(plan.fileNames().getFirst());
        byte[] competing = identical ? plan.bytes(raced.getFileName().toString()) : new byte[] { 7 };
        var hook = new SourceBundleStore.InstallHook() {
            @Override public void afterInstall(int index, Path target) { }
            @Override public void beforeLink(Path target) throws IOException {
                if (target.equals(raced)) Files.write(target, competing, java.nio.file.StandardOpenOption.CREATE_NEW);
            }
        };
        Operation operation = () -> SourceBundleStore.install(directory.resolve("target.dbg.c"), plan, List.of(), () -> false, hook);
        if (identical) {
            operation.run();
            verifyInventory(directory, plan);
        }
        else {
            reject(operation);
            require(!Files.exists(directory.resolve(plan.manifestName())), "exclusive conflict withholds manifest");
        }
        require(Arrays.equals(Files.readAllBytes(raced), competing), "exclusive link never replaces competing bytes");
        try (var files = Files.list(directory)) {
            require(files.noneMatch(path -> path.getFileName().toString().startsWith(".forge-")), "exclusive race stage cleanup");
        }
    }

    private static void cancellation(Path root, SourceBundle.Plan plan) throws Exception {
        AtomicInteger calls = new AtomicInteger();
        Path baseline = Files.createDirectory(root.resolve("cancel-baseline"));
        SourceBundleStore.install(baseline.resolve("target.dbg.c"), plan, List.of(), () -> {
            calls.incrementAndGet(); return false;
        });
        for (int stop = 1; stop <= calls.get(); stop++) {
            Path directory = Files.createDirectory(root.resolve("cancel-" + stop));
            int limit = stop;
            AtomicInteger count = new AtomicInteger();
            try {
                SourceBundleStore.install(directory.resolve("target.dbg.c"), plan, List.of(), () -> count.incrementAndGet() >= limit);
                throw new AssertionError("ignored cancellation at " + stop);
            }
            catch (CancellationException expected) { checks++; }
            verifyInventory(directory, plan);
        }
        System.out.println("source-store-cancellation-points=" + calls.get());
    }

    private static void verifyInventory(Path directory, SourceBundle.Plan plan) throws Exception {
        boolean manifestPresent = Files.exists(directory.resolve(plan.manifestName()));
        for (String name : plan.fileNames()) {
            Path file = directory.resolve(name);
            if (manifestPresent) require(Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS), "manifest references existing part");
            if (Files.exists(file)) require(Arrays.equals(Files.readAllBytes(file), plan.bytes(name)), "installed files complete");
        }
        try (var files = Files.list(directory)) {
            require(files.noneMatch(path -> path.getFileName().toString().startsWith(".forge-")), "no leaked stage");
        }
    }

    @FunctionalInterface private interface Operation { void run() throws Exception; }

    private static void reject(Operation operation) throws Exception {
        try {
            operation.run();
            throw new AssertionError("expected store/publication failure");
        }
        catch (IOException expected) { checks++; }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }
}
