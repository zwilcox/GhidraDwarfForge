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
            writeManifest(directory);

            var pair = PackagedNativeLibraries.resolve(root, "linux_x86_64");
            require(pair.consumer().getFileName().toString().equals("libdwarf.so.2.3.2"),
                "consumer resolution failed");
            require(pair.producer().getFileName().toString().equals("libdwarfp.so.2.3.2"),
                "producer resolution failed");

            write(pair.producer(), "tampered");
            expectFailure(() -> PackagedNativeLibraries.resolve(root, "linux_x86_64"),
                "SHA-256 mismatch");
            expectFailure(() -> PackagedNativeLibraries.resolve(root, "linux_arm_64"),
                "unavailable for host platform");
        }
        finally {
            deleteTree(root);
        }
        System.out.println("packaged-native-libraries=PASS");
    }

    private static void writeManifest(Path directory) throws Exception {
        StringBuilder manifest = new StringBuilder();
        try (var paths = Files.list(directory)) {
            for (Path path : paths.sorted().toList()) {
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
