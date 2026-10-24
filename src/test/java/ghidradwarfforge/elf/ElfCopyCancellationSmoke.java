package ghidradwarfforge.elf;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BooleanSupplier;

import ghidradwarfforge.output.ArtifactPairPublisher;

/** Cancellation during bounded ELF copying and immediately before publication. */
public final class ElfCopyCancellationSmoke {
    private static final long INPUT_SIZE = 128L * 1024 * 1024;
    private static final byte[] PREVIOUS = { 9, 8, 7, 6 };
    private static final Map<String, byte[]> DEBUG = Map.of(".debug_info", new byte[] { 1, 2 });

    private ElfCopyCancellationSmoke() {
    }

    public static void main(String[] args) throws Exception {
        Path directory = Files.createTempDirectory("forge-copy-cancel-");
        try {
            Path input = directory.resolve("input.elf");
            createInput(input);
            byte[] originalHash = hash(input);
            checkDirectCopy(input, directory);
            checkWriter(input, directory, false, false);
            checkWriter(input, directory, true, false);
            checkWriter(input, directory, true, true);
            checkPair(input, directory);
            require(Arrays.equals(originalHash, hash(input)), "cancellation changed the input");
            requireNoStagingFiles(directory);
            System.out.println("elf-copy-cancellation-smoke=PASS");
        }
        finally {
            try (var files = Files.walk(directory)) {
                for (Path path : files.sorted(Comparator.reverseOrder()).toList()) {
                    Files.deleteIfExists(path);
                }
            }
        }
    }

    private static void checkDirectCopy(Path input, Path directory) throws Exception {
        ElfImage image = ElfImage.read(input);
        Path partial = directory.resolve("direct-copy");
        try (FileChannel destination = FileChannel.open(partial, StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE)) {
            try {
                image.copyTo(destination, () -> {
                    try {
                        return destination.position() > 0;
                    }
                    catch (IOException failure) {
                        throw new UncheckedIOException(failure);
                    }
                });
                throw new AssertionError("direct copy ignored cancellation");
            }
            catch (CancellationException expected) {
                require(destination.isOpen(), "copy closed the caller's destination");
                require(destination.position() > 0 && destination.position() < INPUT_SIZE,
                    "direct cancellation did not interrupt an active bounded copy");
                require(destination.position() <= 16L * 1024 * 1024,
                    "copy did not poll within its documented chunk bound");
            }
        }
        Files.delete(partial);
    }

    private static void checkWriter(Path input, Path directory, boolean existing,
            boolean beforeMove) throws Exception {
        Path output = directory.resolve("writer-" + existing + "-" + beforeMove + ".dbg");
        if (existing) {
            Files.write(output, PREVIOUS);
        }
        AtomicLong observed = new AtomicLong();
        try {
            new MatchedElfSidecarWriter().write(input, output, DEBUG,
                cancelAtStaging(directory, beforeMove, observed));
            throw new AssertionError("writer ignored cancellation");
        }
        catch (CancellationException expected) {
            require(observed.get() > 0 && (beforeMove ? observed.get() > INPUT_SIZE :
                observed.get() < INPUT_SIZE), "cancellation occurred at the wrong copy stage");
            require(existing ? Arrays.equals(PREVIOUS, Files.readAllBytes(output)) :
                !Files.exists(output), "cancelled writer changed the final output");
            requireNoStagingFiles(directory);
        }
    }

    private static void checkPair(Path input, Path directory) throws Exception {
        Path artifact = directory.resolve("pair.dbg");
        Path source = directory.resolve("pair.dbg.c");
        Files.write(artifact, PREVIOUS);
        Files.write(source, PREVIOUS);
        AtomicBoolean sourceWritten = new AtomicBoolean();
        AtomicLong observed = new AtomicLong();
        try {
            ArtifactPairPublisher.stageAndPublish(artifact, source,
                staged -> new MatchedElfSidecarWriter().write(input, staged, DEBUG,
                    cancelAtStaging(directory, false, observed)),
                staged -> {
                    sourceWritten.set(true);
                    Files.writeString(staged, "new source");
                }, () -> {
                    // Cancellation must occur inside the original-file copy.
                });
            throw new AssertionError("pair publisher lost copy cancellation");
        }
        catch (CancellationException expected) {
            require(observed.get() > 0 && observed.get() < INPUT_SIZE && !sourceWritten.get(),
                "pair did not stop during artifact copying");
            require(Arrays.equals(PREVIOUS, Files.readAllBytes(artifact)) &&
                Arrays.equals(PREVIOUS, Files.readAllBytes(source)),
                "copy cancellation replaced part of the existing pair");
            requireNoStagingFiles(directory);
        }
    }

    private static BooleanSupplier cancelAtStaging(Path directory, boolean beforeMove,
            AtomicLong observed) {
        return () -> {
            try (var files = Files.list(directory)) {
                Path staged = files.filter(path -> path.getFileName().toString()
                    .startsWith(".ghidra-dwarf-forge-")).findFirst().orElse(null);
                if (staged == null || Files.size(staged) == 0) {
                    return false;
                }
                long size = Files.size(staged);
                if (beforeMove) {
                    if (size <= INPUT_SIZE) {
                        return false;
                    }
                    try (FileChannel file = FileChannel.open(staged, StandardOpenOption.READ)) {
                        ByteBuffer header = ByteBuffer.allocate(64).order(ByteOrder.LITTLE_ENDIAN);
                        while (header.hasRemaining()) {
                            if (file.read(header) < 0) {
                                throw new IOException("truncated staging header");
                            }
                        }
                        if (header.getLong(40) == 0) {
                            return false;
                        }
                    }
                }
                observed.set(size);
                return true;
            }
            catch (IOException failure) {
                throw new UncheckedIOException(failure);
            }
        };
    }

    private static void createInput(Path path) throws IOException {
        ByteBuffer header = ByteBuffer.allocate(120).order(ByteOrder.LITTLE_ENDIAN);
        header.put(new byte[] { 0x7f, 'E', 'L', 'F', 2, 1, 1, 0 });
        header.putShort(16, (short) 2).putShort(18, (short) 62).putInt(20, 1);
        header.putLong(32, 64).putShort(52, (short) 64).putShort(54, (short) 56);
        header.putShort(56, (short) 1).putShort(58, (short) 64);
        header.putInt(64, 1).putInt(68, 4).putLong(80, 0x400000);
        header.putLong(88, 0x400000).putLong(96, INPUT_SIZE).putLong(104, INPUT_SIZE);
        header.putLong(112, 0x1000).position(0);
        try (FileChannel file = FileChannel.open(path, StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE)) {
            while (header.hasRemaining()) {
                file.write(header);
            }
            file.position(INPUT_SIZE - 1);
            file.write(ByteBuffer.wrap(new byte[] { 0x5a }));
        }
    }

    private static byte[] hash(Path path) throws Exception {
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        try (InputStream input = Files.newInputStream(path)) {
            byte[] block = new byte[1024 * 1024];
            int count;
            while ((count = input.read(block)) >= 0) {
                hash.update(block, 0, count);
            }
        }
        return hash.digest();
    }

    private static void requireNoStagingFiles(Path directory) throws IOException {
        try (var files = Files.list(directory)) {
            require(files.noneMatch(path -> path.getFileName().toString()
                .startsWith(".")), "cancellation left a staging/backup file");
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
