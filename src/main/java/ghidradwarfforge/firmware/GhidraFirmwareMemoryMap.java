package ghidradwarfforge.firmware;

import java.io.IOException;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;

import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.output.FileDigests;
import ghidradwarfforge.firmware.FirmwareMemoryMap.FileSpan;
import ghidradwarfforge.firmware.FirmwareMemoryMap.Input;
import ghidradwarfforge.firmware.FirmwareMemoryMap.Region;
import ghidradwarfforge.firmware.FirmwareMemoryMap.Storage;

/** Native-free capture of explicit input bindings; never resolves a file by its basename. */
public final class GhidraFirmwareMemoryMap {
    private static final int CHUNK = 64 * 1024;

    public record BoundInput(String id, Path path, FileBytes fileBytes) {
        public BoundInput {
            Objects.requireNonNull(id, "input ID");
            Objects.requireNonNull(path, "input path");
            Objects.requireNonNull(fileBytes, "Ghidra original file bytes");
        }
    }

    private GhidraFirmwareMemoryMap() { }

    /**
     * Optimistic capture, not a database lock. Callers must also check program and input
     * consistency immediately before publication. Unbacked initialized data, live aliases,
     * overlays, and non-default address spaces require a separate explicit mapping policy.
     */
    public static FirmwareMemoryMap capture(Program program, FirmwareTarget target,
            List<BoundInput> bindings, TaskMonitor monitor)
            throws IOException, CancelledException, MemoryAccessException {
        monitor.checkCancelled();
        requireTarget(program, target);
        long modification = program.getModificationNumber();
        if (target.equals(FirmwareTarget.CORTEX_M3)) {
            ghidradwarfforge.GhidraCortexM3Profile.requireThumbCode(program, monitor);
        }
        var inputs = new ArrayList<Input>();
        var bound = new HashMap<FileBytes, BoundInput>();
        var digests = new HashMap<String, FileDigests.Result>();
        for (BoundInput binding : bindings) {
            monitor.checkCancelled();
            if (bound.putIfAbsent(binding.fileBytes(), binding) != null || digests.containsKey(binding.id())) {
                throw new IllegalArgumentException("duplicate raw firmware input binding");
            }
            if (!program.getMemory().getAllFileBytes().contains(binding.fileBytes())) {
                throw new IllegalArgumentException("firmware FileBytes does not belong to this program");
            }
            var digest = FileDigests.read(binding.path(), monitor::isCancelled);
            inputs.add(new Input(binding.id(), digest.byteCount(), digest.sha256()));
            digests.put(binding.id(), digest);
            requireOriginalBytes(binding, digest.byteCount(), monitor);
        }
        var regions = new ArrayList<Region>();
        var space = program.getAddressFactory().getDefaultAddressSpace();
        for (var block : program.getMemory().getBlocks()) {
            monitor.checkCancelled();
            if (block.isOverlay() || block.isMapped() || block.isExternalBlock() ||
                    !block.isLoaded() || !block.getStart().getAddressSpace().equals(space)) {
                throw new IllegalArgumentException("unsupported firmware overlay, alias or unmapped block: " + block.getName());
            }
            var spans = new ArrayList<FileSpan>();
            if (block.isInitialized()) {
                for (var source : block.getSourceInfos()) {
                    monitor.checkCancelled();
                    var bytes = source.getFileBytes().orElseThrow(() -> new IllegalArgumentException(
                        "initialized firmware block has no original-file provenance: " + block.getName()));
                    BoundInput binding = bound.get(bytes);
                    long offset = source.getFileBytesOffset();
                    long length = source.getLength();
                    if (binding == null || offset < 0 || length <= 0 ||
                            offset > bytes.getSize() - length || source.getMappedRange().isPresent()) {
                        throw new IllegalArgumentException("missing or ambiguous firmware file binding: " + block.getName());
                    }
                    long absoluteOffset = Math.addExact(bytes.getFileOffset(), offset);
                    spans.add(new FileSpan(source.getMinAddress().subtract(block.getStart()),
                        length, binding.id(), absoluteOffset));
                    // A changed analysis byte must not silently masquerade as original firmware.
                    byte[] original = new byte[CHUNK];
                    byte[] current = new byte[CHUNK];
                    for (long done = 0; done < length;) {
                        monitor.checkCancelled();
                        int count = (int) Math.min(CHUNK, length - done);
                        if (bytes.getOriginalBytes(offset + done, original, 0, count) != count ||
                                block.getBytes(source.getMinAddress().add(done), current, 0, count) != count ||
                                !Arrays.equals(original, 0, count, current, 0, count)) {
                            throw new IllegalArgumentException("firmware analysis bytes differ from original input: " + block.getName());
                        }
                        done += count;
                    }
                }
            }
            regions.add(new Region(block.getName(), block.getStart().getOffset(), block.getSize(),
                block.isRead(), block.isWrite(), block.isExecute(),
                block.isInitialized() ? Storage.FILE_BACKED : Storage.UNINITIALIZED, spans));
        }
        var result = new FirmwareMemoryMap(target.addressBits(), inputs, regions);
        for (BoundInput binding : bindings) {
            if (!digests.get(binding.id()).equals(FileDigests.read(binding.path(), monitor::isCancelled))) {
                throw new IOException("original firmware input changed during memory-map capture: " + binding.id());
            }
        }
        monitor.checkCancelled();
        if (program.isClosed() || program.getModificationNumber() != modification) {
            throw new IOException("Ghidra program changed during firmware memory-map capture");
        }
        return result;
    }

    public static void requireTarget(Program program, FirmwareTarget target) {
        target.requireSupported();
        var language = program.getLanguage();
        boolean little = target.byteOrder() == ByteOrder.LITTLE_ENDIAN;
        if (!program.getLanguageID().toString().equals(target.languageId()) ||
                !program.getCompilerSpec().getCompilerSpecID().toString().equals(target.compilerSpecId()) ||
                program.getDefaultPointerSize() * 8 != target.pointerBits() ||
                program.getAddressFactory().getDefaultAddressSpace().getSize() != target.addressBits() ||
                language.isBigEndian() == little ||
                language.getLanguageDescription().getInstructionEndian() != (little ? Endian.LITTLE : Endian.BIG)) {
            throw new IllegalArgumentException("raw firmware target disagrees with Ghidra language, ABI, widths or byte order");
        }
    }

    private static void requireOriginalBytes(BoundInput binding, long inputSize, TaskMonitor monitor)
            throws IOException, CancelledException {
        FileBytes bytes = binding.fileBytes();
        long offset = bytes.getFileOffset();
        long length = bytes.getSize();
        if (offset < 0 || length <= 0 || offset > inputSize - length) {
            throw new IllegalArgumentException("Ghidra file-byte extent is outside original firmware input");
        }
        byte[] imported = new byte[CHUNK];
        byte[] actual = new byte[CHUNK];
        try (var stream = Files.newInputStream(binding.path())) {
            stream.skipNBytes(offset);
            for (long done = 0; done < length;) {
                monitor.checkCancelled();
                int count = (int) Math.min(CHUNK, length - done);
                if (bytes.getOriginalBytes(done, imported, 0, count) != count ||
                        stream.readNBytes(actual, 0, count) != count ||
                        !Arrays.equals(imported, 0, count, actual, 0, count)) {
                    throw new IllegalArgumentException("Ghidra original bytes do not match firmware input: " + binding.id());
                }
                done += count;
            }
        }
    }
}
