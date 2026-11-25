package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

/** Per-output writer claims and a recovery inventory for an interrupted multi-name commit. */
final class PublicationJournal {
    private static final String CLAIM_PREFIX = ".ghidra-dwarf-forge-publishing-";
    static final String INVENTORY = "generation.properties";
    private static final String OWNER = "owner.properties";
    private final Path directory;
    private final Map<Path, Path> backupDirectories = new HashMap<>();
    private final List<Path> claims = new ArrayList<>();

    PublicationJournal(Path directory) {
        this.directory = directory;
        backupDirectories.put(directory.getParent(), directory);
    }

    Path backup(int index, Path target) throws IOException {
        Path parent = target.getParent();
        Path backups = backupDirectories.get(parent);
        if (backups == null) {
            backups = Files.createTempDirectory(parent, ".forge-generation-");
            backupDirectories.put(parent, backups);
        }
        return backups.resolve("backup-" + index);
    }

    static Path claimPath(Path target) throws IOException {
        Path leaf = target.getFileName();
        try {
            leaf = target.toRealPath(LinkOption.NOFOLLOW_LINKS).getFileName();
        }
        catch (java.nio.file.NoSuchFileException missing) {
            // A new output uses its selected name.
        }
        // Case and normalization aliases must contend on filesystems that equate them.
        String name = Normalizer.normalize(leaf.toString().toLowerCase(Locale.ROOT), Normalizer.Form.NFC);
        try {
            byte[] key = MessageDigest.getInstance("SHA-256").digest(name.getBytes(StandardCharsets.UTF_8));
            return target.resolveSibling(CLAIM_PREFIX + HexFormat.of().formatHex(key));
        }
        catch (NoSuchAlgorithmException impossible) { throw new AssertionError(impossible); }
    }

    void prepare(Properties inventory, List<Path> targets) throws IOException {
        inventory.setProperty("version", "1");
        inventory.setProperty("recovery", "Confirm the owner process has stopped. Preserve listed backups and stages. " +
            "Match every file to its old or new SHA-256 or symlink target before restoring a complete generation. " +
            "Preserve divergent files. Release the claims only after verifying all outputs.");
        inventory.setProperty("pid", Long.toString(ProcessHandle.current().pid()));
        inventory.setProperty("count", Integer.toString(targets.size()));
        List<Path> required = new ArrayList<>();
        for (int index = 0; index < targets.size(); index++) {
            Path claim = claimPath(targets.get(index));
            inventory.setProperty("file." + index + ".claim", claim.toString());
            required.add(claim);
        }
        writeProperties(directory.resolve(INVENTORY), inventory);
        Properties owner = new Properties();
        owner.setProperty("inventory", directory.resolve(INVENTORY).toString());
        owner.setProperty("pid", inventory.getProperty("pid"));
        for (Path backups : backupDirectories.values()) {
            writeProperties(backups.resolve(OWNER), owner);
        }
        for (Path claim : required.stream().distinct().sorted().toList()) {
            try {
                Files.createLink(claim, backupDirectories.get(claim.getParent()).resolve(OWNER));
            }
            catch (IOException busy) {
                if (!Files.exists(claim, LinkOption.NOFOLLOW_LINKS)) throw busy;
                throw new IOException("Another export is publishing here or needs recovery after interruption. " +
                    recoveryLocation(claim), busy);
            }
            claims.add(claim);
        }
    }

    private String recoveryLocation(Path claim) throws IOException {
        if (Files.isRegularFile(claim, LinkOption.NOFOLLOW_LINKS)) return "Inspect " + claim + " before retrying";
        Path legacyOwner = claim.resolve(OWNER);
        if (Files.isDirectory(claim, LinkOption.NOFOLLOW_LINKS) &&
                Files.isRegularFile(legacyOwner, LinkOption.NOFOLLOW_LINKS)) {
            return "Inspect " + legacyOwner + " before retrying";
        }
        // Older writers could stop between creating their claim directory and recording its owner.
        List<Path> candidates = new ArrayList<>();
        for (Path parent : backupDirectories.keySet()) {
            try (var siblings = Files.newDirectoryStream(parent, ".forge-generation-*")) {
                for (Path sibling : siblings) {
                    Path inventory = sibling.resolve(INVENTORY);
                    if (sibling.equals(directory) || !Files.isDirectory(sibling, LinkOption.NOFOLLOW_LINKS) ||
                            !Files.isRegularFile(inventory, LinkOption.NOFOLLOW_LINKS)) continue;
                    Properties previous = new Properties();
                    try (var stream = Files.newInputStream(inventory, LinkOption.NOFOLLOW_LINKS)) {
                        previous.load(stream);
                    }
                    catch (IOException | IllegalArgumentException unreadable) { continue; }
                    if (previous.stringPropertyNames().stream().anyMatch(key -> key.matches("file\\.\\d+\\.claim") &&
                            claim.toString().equals(previous.getProperty(key)))) candidates.add(inventory);
                }
            }
        }
        return "Preserve the incomplete claim " + claim + " and all stages and backups. " +
            (candidates.isEmpty() ? "No matching recovery inventory found in " + backupDirectories.keySet() :
                "Inspect matching recovery inventories " + candidates);
    }

    private static void writeProperties(Path path, Properties properties) throws IOException {
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            properties.store(Channels.newOutputStream(channel), "GhidraDwarfForge ordinary export recovery");
            channel.force(true);
        }
    }

    // A process interruption before this marker leaves both generations identifiable by hash.
    void committed() throws IOException {
        Files.createFile(directory.resolve("committed"));
    }

    void removeInventories() throws IOException {
        Files.deleteIfExists(directory.resolve("committed"));
        Files.deleteIfExists(directory.resolve(INVENTORY));
        for (Path backups : backupDirectories.values()) {
            Files.deleteIfExists(backups.resolve(OWNER));
            if (!backups.equals(directory)) Files.delete(backups);
        }
    }

    void release() throws IOException {
        IOException failure = null;
        for (Path claim : claims.reversed()) {
            try {
                Properties record = new Properties();
                try (var input = Files.newInputStream(claim, LinkOption.NOFOLLOW_LINKS)) {
                    record.load(input);
                }
                catch (IllegalArgumentException malformed) {
                    throw new IOException("Unreadable publication claim at " + claim, malformed);
                }
                if (!directory.resolve(INVENTORY).toString().equals(record.getProperty("inventory"))) {
                    throw new IOException("Publication claim changed during export: " + claim);
                }
                Files.delete(claim);
            }
            catch (IOException problem) {
                if (failure == null) failure = problem;
                else failure.addSuppressed(problem);
            }
        }
        if (failure != null) throw failure;
    }
}
