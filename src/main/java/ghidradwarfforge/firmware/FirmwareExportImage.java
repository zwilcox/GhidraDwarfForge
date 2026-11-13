package ghidradwarfforge.firmware;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.output.FileDigests;

/**
 * Explicit synthetic target adapter, not an original executable. The private witness
 * carries mapped bytes for existing code/ABI evidence checks; the publication image
 * carries only NOBITS allocations. Both have zero entry point, no program headers,
 * no original symbols, no build ID and no inherited debug or unwind information.
 */
public final class FirmwareExportImage implements AutoCloseable {
    private static final int MAX_REGIONS = 16384;
    private static final int CHUNK = 64 * 1024;
    private final Path directory;
    private final FirmwareTarget target;
    private final FirmwareMemoryMap map;
    private final Map<String, Path> inputs;
    private final ElfImage witness;
    private final ElfImage allocations;

    private FirmwareExportImage(Path directory, FirmwareTarget target, FirmwareMemoryMap map,
            Map<String, Path> inputs, ElfImage witness, ElfImage allocations) {
        this.directory = directory;
        this.target = target;
        this.map = map;
        this.inputs = Map.copyOf(inputs);
        this.witness = witness;
        this.allocations = allocations;
    }

    public FirmwareTarget target() { return target; }
    public FirmwareMemoryMap memoryMap() { return map; }
    public ElfImage witness() { return witness; }
    public ElfImage allocations() { return allocations; }
    public Path witnessPath() { return directory.resolve("witness.elf"); }

    public static FirmwareExportImage open(FirmwareTarget target, FirmwareMemoryMap map,
            Map<String, Path> inputPaths, BooleanSupplier cancelled) throws IOException {
        checkCancelled(cancelled);
        target.requireSupported();
        if (map.addressBits() != target.addressBits() || map.regions().size() > MAX_REGIONS) {
            throw new IllegalArgumentException("firmware map width or region count is unsupported");
        }
        var inputs = new HashMap<String, Path>();
        for (var input : map.inputs()) {
            Path path = inputPaths.get(input.id());
            if (path == null) throw new IllegalArgumentException("missing firmware input path: " + input.id());
            inputs.put(input.id(), path.toRealPath());
        }
        if (!inputs.keySet().equals(inputPaths.keySet())) {
            throw new IllegalArgumentException("firmware input paths differ from the captured map");
        }
        requireInputs(map, inputs, cancelled);
        Path directory = Files.createTempDirectory("forge-firmware-image-");
        try {
            Path witness = directory.resolve("witness.elf");
            Path allocations = directory.resolve("allocations.elf");
            write(target, map, inputs, witness, true, cancelled);
            write(target, map, inputs, allocations, false, cancelled);
            requireInputs(map, inputs, cancelled);
            return new FirmwareExportImage(directory, target, map, inputs,
                ElfImage.read(witness), ElfImage.read(allocations));
        }
        catch (IOException | RuntimeException | Error failure) {
            try { remove(directory); }
            catch (IOException cleanup) { failure.addSuppressed(cleanup); }
            throw failure;
        }
    }

    public void requireInputsUnchanged(BooleanSupplier cancelled) throws IOException {
        requireInputs(map, inputs, cancelled);
    }

    public void requireSafeOutput(Path output) throws IOException {
        Path destination = ghidradwarfforge.output.FileSystemPaths.resolveLeaf(output, "firmware output");
        for (Path input : inputs.values()) {
            if (ghidradwarfforge.output.FileSystemPaths.aliases(destination, input)) {
                throw new IOException("firmware output aliases an original input: " + input);
            }
        }
    }

    private static void requireInputs(FirmwareMemoryMap map, Map<String, Path> inputs,
            BooleanSupplier cancelled) throws IOException {
        for (var input : map.inputs()) {
            checkCancelled(cancelled);
            var digest = FileDigests.read(inputs.get(input.id()), cancelled);
            if (digest.byteCount() != input.size() || !digest.sha256().equals(input.sha256())) {
                throw new IOException("firmware input differs from captured provenance: " + input.id());
            }
        }
    }

    private record Section(String name, long type, long flags, long address, long offset,
            long size, byte[] payload) { }

    private static void write(FirmwareTarget target, FirmwareMemoryMap map, Map<String, Path> inputs,
            Path output, boolean includeBytes, BooleanSupplier cancelled) throws IOException {
        boolean wide = target.addressBits() == 64;
        int headerSize = wide ? 64 : 52;
        int sectionSize = wide ? 64 : 40;
        var sections = new ArrayList<Section>();
        sections.add(new Section("", 0, 0, 0, 0, 0, new byte[0]));
        try (var channel = FileChannel.open(output, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            channel.position(headerSize);
            int index = 0;
            for (var region : map.regions()) {
                checkCancelled(cancelled);
                boolean backed = includeBytes && region.storage() == FirmwareMemoryMap.Storage.FILE_BACKED;
                long offset = backed ? channel.position() : 0;
                if (backed) {
                    for (var span : region.spans()) copy(channel, inputs.get(span.inputId()), span, cancelled);
                }
                sections.add(new Section(".forge.region." + index++, backed ? 1 : 8,
                    2 | (region.write() ? 1 : 0) | (region.execute() ? 4 : 0),
                    region.address(), offset, region.length(), new byte[0]));
            }
            // Profile metadata is declared explicitly, not recovered compiler metadata.
            for (var metadata : target.metadataSections()) {
                byte[] attributes = metadata.bytes();
                sections.add(new Section(metadata.name(), metadata.type(), 0, 0,
                    channel.position(), attributes.length, attributes));
                writeAll(channel, ByteBuffer.wrap(attributes), cancelled);
            }
            byte[] marker = ("GhidraDwarfForge synthetic firmware debug container\n" +
                "target-profile=" + target.profile() + "\nno original ELF identity or load image\n")
                .getBytes(StandardCharsets.UTF_8);
            sections.add(new Section(".forge.firmware", 1, 0, 0, channel.position(), marker.length, marker));
            writeAll(channel, ByteBuffer.wrap(marker), cancelled);
            int namesIndex = sections.size();
            var names = new ByteArrayOutputStream();
            var nameOffsets = new ArrayList<Integer>();
            for (var section : sections) {
                nameOffsets.add(names.size());
                names.writeBytes(section.name().getBytes(StandardCharsets.UTF_8));
                names.write(0);
            }
            nameOffsets.add(names.size());
            names.writeBytes(".shstrtab\0".getBytes(StandardCharsets.UTF_8));
            byte[] stringTable = names.toByteArray();
            sections.add(new Section(".shstrtab", 3, 0, 0, channel.position(), stringTable.length, stringTable));
            writeAll(channel, ByteBuffer.wrap(stringTable), cancelled);
            int padding = (int) ((8 - channel.position() % 8) % 8);
            writeAll(channel, ByteBuffer.allocate(padding), cancelled);
            long sectionOffset = channel.position();
            for (int i = 0; i < sections.size(); i++) {
                Section section = sections.get(i);
                var bytes = ByteBuffer.allocate(sectionSize).order(target.byteOrder());
                if (i == 0) {
                    writeAll(channel, bytes, cancelled);
                    continue;
                }
                bytes.putInt(nameOffsets.get(i)).putInt(u32(section.type()));
                if (wide) {
                    bytes.putLong(section.flags()).putLong(section.address()).putLong(section.offset())
                        .putLong(section.size()).putInt(0).putInt(0).putLong(1).putLong(0);
                }
                else {
                    bytes.putInt(u32(section.flags())).putInt(u32(section.address())).putInt(u32(section.offset()))
                        .putInt(u32(section.size())).putInt(0).putInt(0).putInt(1).putInt(0);
                }
                bytes.flip();
                writeAll(channel, bytes, cancelled);
            }
            var header = ByteBuffer.allocate(headerSize).order(target.byteOrder());
            header.put(new byte[] {0x7f, 'E', 'L', 'F', (byte) (wide ? 2 : 1),
                (byte) (target.byteOrder() == java.nio.ByteOrder.LITTLE_ENDIAN ? 1 : 2), 1});
            header.position(16);
            header.putShort((short) 2).putShort((short) target.machine()).putInt(1);
            if (wide) header.putLong(0).putLong(0).putLong(sectionOffset);
            else header.putInt(0).putInt(0).putInt(u32(sectionOffset));
            header.putInt(u32(target.elfFlags())).putShort((short) headerSize)
                .putShort((short) 0).putShort((short) 0).putShort((short) sectionSize)
                .putShort((short) sections.size()).putShort((short) namesIndex).flip();
            channel.position(0);
            writeAll(channel, header, cancelled);
        }
    }

    private static int u32(long value) {
        if (value < 0 || value > 0xffff_ffffL) {
            throw new IllegalArgumentException("firmware ELF32 field exceeds unsigned 32-bit range; split oversized regions");
        }
        return (int) value;
    }

    private static void copy(FileChannel output, Path path, FirmwareMemoryMap.FileSpan span,
            BooleanSupplier cancelled) throws IOException {
        try (var input = FileChannel.open(path, StandardOpenOption.READ)) {
            var bytes = ByteBuffer.allocate(CHUNK);
            long offset = span.fileOffset();
            long remaining = span.length();
            while (remaining > 0) {
                checkCancelled(cancelled);
                bytes.clear().limit((int) Math.min(CHUNK, remaining));
                int count = input.read(bytes, offset);
                if (count <= 0) throw new IOException("firmware input truncated while building byte witness");
                bytes.flip();
                writeAll(output, bytes, cancelled);
                offset += count;
                remaining -= count;
            }
        }
    }

    private static void writeAll(FileChannel channel, ByteBuffer bytes, BooleanSupplier cancelled) throws IOException {
        while (bytes.hasRemaining()) {
            checkCancelled(cancelled);
            if (channel.write(bytes) <= 0) throw new IOException("firmware metadata write made no progress");
        }
    }

    private static void checkCancelled(BooleanSupplier cancelled) {
        if (Objects.requireNonNull(cancelled, "cancelled").getAsBoolean()) {
            throw new CancellationException("firmware image preparation cancelled");
        }
    }

    @Override
    public void close() throws IOException { remove(directory); }

    private static void remove(Path directory) throws IOException {
        IOException failure = null;
        for (Path path : List.of(directory.resolve("witness.elf"), directory.resolve("allocations.elf"), directory)) {
            try { Files.deleteIfExists(path); }
            catch (IOException error) {
                if (failure == null) failure = error;
                else failure.addSuppressed(error);
            }
        }
        if (failure != null) throw failure;
    }
}
