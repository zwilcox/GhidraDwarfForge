package ghidradwarfforge.nativeapi;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;

public final class PackagedNativeLibrariesSmoke {
    private PackagedNativeLibrariesSmoke() {
    }

    public static void main(String[] arguments) throws Exception {
        Path root = Files.createTempDirectory("forge-packaged-native-smoke-");
        try {
            Path directory = root.resolve("os/linux_x86_64");
            Files.createDirectories(directory);
            write(directory.resolve("libdwarf.so.2.3.2"), "consumer");
            write(directory.resolve("libdwarfp.so.2.3.2"), "producer");
            write(directory.resolve("NATIVE-PAIR.properties"),
                "consumer=libdwarf.so.2.3.2\nproducer=libdwarfp.so.2.3.2\n");
            write(directory.resolve("forge-validator-supervisor"), "supervisor");
            writeManifest(directory);

            var pair = PackagedNativeLibraries.resolve(root, "linux_x86_64");
            require(pair.consumer().getFileName().toString().equals("libdwarf.so.2.3.2"),
                "consumer resolution failed");
            require(pair.producer().getFileName().toString().equals("libdwarfp.so.2.3.2"),
                "producer resolution failed");
            require(PackagedNativeLibraries.resolveSupervisor(root, "linux_x86_64").equals(
                directory.resolve("forge-validator-supervisor")), "supervisor resolution failed");

            write(directory.resolve("forge-validator-supervisor"), "tampered helper");
            expectFailure(() -> PackagedNativeLibraries.resolveSupervisor(root, "linux_x86_64"), "SHA-256 mismatch");
            write(directory.resolve("forge-validator-supervisor"), "supervisor");

            write(pair.producer(), "tampered");
            expectFailure(() -> PackagedNativeLibraries.resolve(root, "linux_x86_64"),
                "SHA-256 mismatch");
            expectFailure(() -> PackagedNativeLibraries.resolve(root, "linux_arm_64"),
                "unavailable for host platform");
            write(pair.producer(), "producer");
            metadataControls(root, directory);

            // Resolve Windows package names on any host without loading fake DLLs.
            Path windows = Files.createDirectories(root.resolve("os/win_x86_64"));
            write(windows.resolve("consumer.dll"), "consumer fixture");
            write(windows.resolve("producer.dll"), "producer fixture");
            write(windows.resolve("forge-validator-supervisor.exe"), "supervisor fixture");
            write(windows.resolve("NATIVE-PAIR.properties"), "consumer=consumer.dll\nproducer=producer.dll\n");
            writeManifest(windows);
            var winPair = PackagedNativeLibraries.resolve(root, "win_x86_64");
            require(winPair.consumer().equals(windows.toRealPath().resolve("consumer.dll")) &&
                winPair.producer().equals(windows.toRealPath().resolve("producer.dll")), "Windows pair names changed");
            require(PackagedNativeLibraries.resolveSupervisor(root, "win_x86_64").equals(
                windows.toRealPath().resolve("forge-validator-supervisor.exe")), "Windows supervisor suffix lost");
        }
        finally {
            deleteTree(root);
        }
        System.out.println("packaged-native-libraries=PASS");
    }

    private static void metadataControls(Path root, Path directory) throws Exception {
        Path pairFile = directory.resolve("NATIVE-PAIR.properties");
        Path sums = directory.resolve("SHA256SUMS");
        String pairText = Files.readString(pairFile);
        String manifest = Files.readString(sums);
        for (Path missing : java.util.List.of(pairFile, sums)) {
            String contents = Files.readString(missing);
            Files.delete(missing);
            expectFailure(() -> PackagedNativeLibraries.resolve(root, "linux_x86_64"), "metadata is missing");
            write(missing, contents);
        }
        for (String key : java.util.List.of("consumer", "producer")) {
            for (String invalid : java.util.Arrays.asList(null, "", " ", ".", "..", "../outside", "/absolute")) {
                String other = key.equals("consumer") ? "producer=libdwarfp.so.2.3.2\n" : "consumer=libdwarf.so.2.3.2\n";
                write(pairFile, other + (invalid == null ? "" : key + "=" + invalid + "\n"));
                writeManifest(directory);
                expectFailure(() -> PackagedNativeLibraries.resolve(root, "linux_x86_64"), "invalid " + key + " entry");
            }
            write(pairFile, pairText.replace(key + "=" + (key.equals("consumer") ? "libdwarf.so.2.3.2" : "libdwarfp.so.2.3.2"),
                key + "=absent-library"));
            writeManifest(directory);
            expectFailure(() -> PackagedNativeLibraries.resolve(root, "linux_x86_64"), "native pair is not covered");
        }
        write(pairFile, pairText);
        write(sums, manifest);
        for (String invalid : java.util.List.of("", "\n \t\n", "bad checksum line\n", "a".repeat(64) + " file\n",
                "a".repeat(64) + "  ../outside\n", "a".repeat(64) + "  sub\\name\n",
                "a".repeat(64) + "  SHA256SUMS\n", manifest + manifest)) {
            write(sums, invalid);
            expectFailure(() -> PackagedNativeLibraries.resolve(root, "linux_x86_64"),
                invalid.isBlank() ? "empty packaged" : invalid.contains("SHA256SUMS") || invalid.equals(manifest + manifest) ?
                    "duplicate/invalid checksum" : "invalid checksum line");
        }
        write(sums, "\n \t\n" + manifest + "\n");
        require(PackagedNativeLibraries.resolve(root, "linux_x86_64").directory().equals(directory.toRealPath()),
            "blank manifest lines changed native pair resolution");
        Path extra = directory.resolve("unmanifested-library");
        write(extra, "not covered");
        expectFailure(() -> PackagedNativeLibraries.resolve(root, "linux_x86_64"), "file set does not match");
        Files.delete(extra);
        Path supervisor = directory.resolve("forge-validator-supervisor");
        Files.delete(supervisor);
        writeManifest(directory);
        expectFailure(() -> PackagedNativeLibraries.resolveSupervisor(root, "linux_x86_64"), "supervisor is missing");
        write(supervisor, "supervisor");
        writeManifest(directory);
        require(Files.readString(sums).equals(manifest), "retry changed deterministic package manifest");
        require(Files.readString(pairFile).equals(pairText), "native metadata controls lost original pair declaration");
    }

    private static void writeManifest(Path directory) throws Exception {
        StringBuilder manifest = new StringBuilder();
        try (var paths = Files.list(directory)) {
            for (Path path : paths.filter(Files::isRegularFile)
                    .filter(p -> !p.getFileName().toString().equals("SHA256SUMS")).sorted().toList()) {
                manifest.append(sha256(path)).append("  ")
                    .append(path.getFileName()).append('\n');
            }
        }
        write(directory.resolve("SHA256SUMS"), manifest.toString());
    }

    private static String sha256(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(Files.readAllBytes(path));
        return HexFormat.of().formatHex(digest.digest());
    }

    private static void write(Path path, String value) throws Exception {
        Files.writeString(path, value, StandardCharsets.UTF_8);
    }

    private static void expectFailure(ThrowingAction action, String message) throws Exception {
        try {
            action.run();
            throw new AssertionError("expected failure containing: " + message);
        }
        catch (java.io.IOException expected) {
            require(expected.getMessage().contains(message),
                "unexpected failure: " + expected.getMessage());
        }
    }

    private static void deleteTree(Path root) throws Exception {
        if (!Files.exists(root)) {
            return;
        }
        try (var paths = Files.walk(root)) {
            for (Path path : paths.sorted(java.util.Comparator.reverseOrder()).toList()) {
                Files.delete(path);
            }
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    @FunctionalInterface
    private interface ThrowingAction {
        void run() throws Exception;
    }
}
