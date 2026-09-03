package ghidradwarfforge.nativeapi;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.framework.Platform;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;

/** Resolves and verifies the native pair bundled in an installed extension. */
public final class PackagedNativeLibraries {
    private static final String MODULE_NAME = "GhidraDwarfForge";
    private static final String PAIR_FILE = "NATIVE-PAIR.properties";
    private static final String CHECKSUM_FILE = "SHA256SUMS";
    private static final Set<String> SUPPORTED_PLATFORMS = Set.of(
        "linux_x86_64", "win_x86_64");

    private PackagedNativeLibraries() {
    }

    public record Pair(Path consumer, Path producer, Path directory) {
    }

    public static Pair resolve() throws IOException {
        ResourceFile moduleRoot = Application.getModuleRootDir(MODULE_NAME);
        if (moduleRoot == null) {
            throw new IOException("installed GhidraDwarfForge module was not found");
        }
        return resolve(moduleRoot.getFile(false).toPath(),
            Platform.CURRENT_PLATFORM.getDirectoryName());
    }

    public static Pair resolve(Path moduleRoot, String platformDirectory) throws IOException {
        if (!SUPPORTED_PLATFORMS.contains(platformDirectory)) {
            throw new IOException("packaged libdwarf is unavailable for host platform " +
                platformDirectory + "; use explicit --libdwarf and --libdwarfp paths");
        }
        Path directory = moduleRoot.toAbsolutePath().normalize()
            .resolve("os").resolve(platformDirectory);
        Path pairFile = directory.resolve(PAIR_FILE);
        Path checksumFile = directory.resolve(CHECKSUM_FILE);
        if (!Files.isRegularFile(pairFile) || !Files.isRegularFile(checksumFile)) {
            throw new IOException("packaged native metadata is missing from " + directory);
        }

        Properties pairProperties = new Properties();
        try (var reader = Files.newBufferedReader(pairFile, StandardCharsets.UTF_8)) {
            pairProperties.load(reader);
        }
        String consumerName = requireBaseName(pairProperties, "consumer");
        String producerName = requireBaseName(pairProperties, "producer");
        Map<String, String> expectedHashes = readChecksums(checksumFile);
        Set<String> actualFiles = new TreeSet<>();
        try (var files = Files.list(directory)) {
            files.filter(Files::isRegularFile)
                .map(path -> path.getFileName().toString())
                .filter(name -> !name.equals(CHECKSUM_FILE))
                .forEach(actualFiles::add);
        }
        if (!actualFiles.equals(new TreeSet<>(expectedHashes.keySet()))) {
            throw new IOException("packaged native file set does not match " + checksumFile);
        }
        for (Map.Entry<String, String> entry : expectedHashes.entrySet()) {
            Path file = directory.resolve(entry.getKey());
            String actualHash = sha256(file);
            if (!actualHash.equals(entry.getValue())) {
                throw new IOException("packaged native SHA-256 mismatch for " + file);
            }
        }
        Path consumer = directory.resolve(consumerName);
        Path producer = directory.resolve(producerName);
        if (!expectedHashes.containsKey(consumerName) ||
                !expectedHashes.containsKey(producerName)) {
            throw new IOException("native pair is not covered by " + checksumFile);
        }
        return new Pair(consumer, producer, directory);
    }

    private static String requireBaseName(Properties properties, String key) throws IOException {
        String value = properties.getProperty(key);
        if (value == null || value.isBlank() || value.equals(".") || value.equals("..") ||
                !Path.of(value).getFileName().toString().equals(value)) {
            throw new IOException("invalid " + key + " entry in " + PAIR_FILE);
        }
        return value;
    }

    private static Map<String, String> readChecksums(Path checksumFile) throws IOException {
        Map<String, String> result = new HashMap<>();
        for (String line : Files.readAllLines(checksumFile, StandardCharsets.UTF_8)) {
            if (line.isBlank()) {
                continue;
            }
            if (!line.matches("[0-9a-f]{64}  [^/\\\\]+")) {
                throw new IOException("invalid checksum line in " + checksumFile + ": " + line);
            }
            String hash = line.substring(0, 64);
            String name = line.substring(66);
            if (name.equals(CHECKSUM_FILE) || result.put(name, hash) != null) {
                throw new IOException("duplicate/invalid checksum entry " + name);
            }
        }
        if (result.isEmpty()) {
            throw new IOException("empty packaged native checksum manifest " + checksumFile);
        }
        return result;
    }

    private static String sha256(Path file) throws IOException {
        final MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        }
        catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
        try (InputStream input = Files.newInputStream(file)) {
            byte[] buffer = new byte[64 * 1024];
            for (int count; (count = input.read(buffer)) >= 0;) {
                digest.update(buffer, 0, count);
            }
        }
        return HexFormat.of().formatHex(digest.digest());
    }
}
