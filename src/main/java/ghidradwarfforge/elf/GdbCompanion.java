package ghidradwarfforge.elf;

import ghidradwarfforge.output.FileDigests;
import ghidradwarfforge.output.FileSystemPaths;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/** Deterministic, explicit GDB companion generation. Does not publish files. */
public final class GdbCompanion {
    private static final long MAX_CHECK_BYTES = 1024L * 1024 * 1024;
    private static final int MAX_SEGMENTS = 1024;
    private record Probe(long offset, long address, long size) {
    }

    private GdbCompanion() {
    }

    /**
     * Bind completed staging bytes to their final selected paths. The caller
     * must publish the companion, sidecar and source as one recoverable set.
     * Input identity/layout is checked independently of opaque report claims.
     */
    public static String render(Path original, Path stagedSidecar, Path stagedSource,
            Path finalSidecar, Path finalSource, BooleanSupplier cancelled) throws IOException {
        Objects.requireNonNull(cancelled, "cancelled");
        checkCancelled(cancelled);
        Path target = original.toRealPath();
        Path sidecar = FileSystemPaths.resolveLeaf(finalSidecar, "sidecar");
        Path source = FileSystemPaths.resolveLeaf(finalSource, "source");
        requirePath(target);
        requirePath(sidecar);
        requirePath(source);
        var originalHash = FileDigests.read(target, cancelled);
        var sidecarHash = FileDigests.read(stagedSidecar, cancelled);
        var sourceHash = FileDigests.read(stagedSource, cancelled);
        if (MatchedElfPrefix.compare(target, stagedSidecar, cancelled).status() !=
                MatchedElfPrefix.Status.MATCHING_COPIED_PREFIX ||
                MatchedElfAllocations.compare(target, stagedSidecar, cancelled).status() !=
                MatchedElfAllocations.Status.MATCHING_ALLOCATED_METADATA) {
            throw new IOException("GDB companion requires a matched Forge sidecar for the selected input");
        }
        ElfImage image = ElfImage.read(target);
        List<ElfImage.Segment> loads = image.segments().stream()
            .filter(segment -> segment.type == 1).toList();
        if (loads.isEmpty() || loads.size() > MAX_SEGMENTS) {
            throw new IOException("GDB companion requires a bounded ELF LOAD table");
        }
        List<Probe> probes = new ArrayList<>();
        boolean executable = false;
        for (var segment : loads) {
            checkCancelled(cancelled);
            if ((segment.flags & 1) != 0 && segment.fileSize > 0) {
                if ((segment.flags & 2) != 0) {
                    throw new IOException("GDB companion cannot establish immutable identity from writable executable LOAD bytes");
                }
                executable = true;
                addProbes(probes, image, segment.offset, segment.virtualAddress, segment.fileSize);
            }
            else if (segment.offset == 0 && segment.fileSize >= image.headerBytes().length) {
                // Include class/order/machine/ABI identity when the ELF header
                // is mapped, including stripped and sectionless executables.
                addProbes(probes, image, 0, segment.virtualAddress, image.headerBytes().length);
            }
        }
        long total = 0;
        for (Probe probe : probes) {
            if (probe.size() > MAX_CHECK_BYTES - total) {
                throw new IOException("GDB companion runtime identity checks exceed 1 GiB");
            }
            total += probe.size();
        }
        if (!executable || probes.size() > MAX_SEGMENTS) {
            throw new IOException("GDB companion requires bounded immutable executable identity evidence");
        }
        StringBuilder manifest = new StringBuilder();
        manifest.append("{\"schema\":1,\"address_bits\":").append(image.is64Bit() ? 64 : 32);
        artifact(manifest, "target", target, originalHash.sha256());
        artifact(manifest, "sidecar", sidecar, sidecarHash.sha256());
        artifact(manifest, "source", source, sourceHash.sha256());
        manifest.append(",\"segments\":[");
        for (int index = 0; index < loads.size(); index++) {
            var segment = loads.get(index);
            if (index != 0) {
                manifest.append(',');
            }
            manifest.append('[').append(segment.offset).append(',').append(segment.virtualAddress)
                .append(',').append(segment.fileSize).append(',').append(segment.memorySize).append(']');
        }
        manifest.append("],\"checks\":[");
        try (FileChannel channel = FileChannel.open(target, StandardOpenOption.READ)) {
            for (int index = 0; index < probes.size(); index++) {
                Probe probe = probes.get(index);
                if (index != 0) {
                    manifest.append(',');
                }
                manifest.append("{\"address\":").append(probe.address())
                    .append(",\"size\":").append(probe.size()).append(",\"sha256\":")
                    .append(quote(digest(channel, probe, cancelled))).append('}');
            }
        }
        manifest.append("]}");
        if (!originalHash.equals(FileDigests.read(target, cancelled)) ||
                !sidecarHash.equals(FileDigests.read(stagedSidecar, cancelled)) ||
                !sourceHash.equals(FileDigests.read(stagedSource, cancelled))) {
            throw new IOException("selected artifacts changed during GDB companion generation");
        }
        byte[] runtime;
        try (var stream = GdbCompanion.class.getResourceAsStream("/ghidradwarfforge/gdb/loader.py")) {
            if (stream == null) {
                throw new IOException("packaged GDB companion runtime is missing");
            }
            runtime = stream.readAllBytes();
        }
        checkCancelled(cancelled);
        String encodedRuntime = Base64.getEncoder().encodeToString(runtime);
        String encodedManifest = Base64.getEncoder().encodeToString(
            manifest.toString().getBytes(StandardCharsets.UTF_8));
        return """
            # GhidraDwarfForge companion. Explicitly source this file in GDB.
            # Registration alone does not load symbols or modify user configuration.
            def _forge_register_companion():
                import base64
                import hashlib
                import json
                import types
                import gdb
                runtime = base64.b64decode('%s')
                digest = hashlib.sha256(runtime).hexdigest()
                previous = getattr(gdb, '_forge_loader_runtime_sha256', None)
                if previous is not None and previous != digest:
                    raise gdb.GdbError('Forge loader runtime differs; use a fresh GDB session')
                module = getattr(gdb, '_forge_loader_runtime_module', None)
                if module is None:
                    module = types.ModuleType('_forge_loader_runtime')
                    exec(compile(runtime, '<Forge loader runtime>', 'exec'), module.__dict__)
                manifest = json.loads(base64.b64decode('%s'))
                module.register(manifest)
                gdb._forge_loader_runtime_sha256 = digest
                gdb._forge_loader_runtime_module = module
            _forge_register_companion()
            del _forge_register_companion
            """.formatted(encodedRuntime, encodedManifest);
    }

    private static void addProbes(List<Probe> probes, ElfImage image,
            long offset, long address, long size) {
        // Attachment changes only section-table fields in a mapped ELF header.
        // Exclude those fields from memory matching; retained executable bytes,
        // other header identity and program headers remain authoritative.
        long[][] ignored = image.is64Bit() ? new long[][] {{40, 48}, {58, 64}}
            : new long[][] {{32, 36}, {46, 52}};
        long cursor = offset;
        long end = Math.addExact(offset, size);
        for (long[] range : ignored) {
            if (range[0] >= end || range[1] <= cursor) {
                continue;
            }
            if (range[0] > cursor) {
                probes.add(new Probe(cursor, address + cursor - offset, range[0] - cursor));
            }
            cursor = Math.min(end, range[1]);
        }
        if (cursor < end) {
            probes.add(new Probe(cursor, address + cursor - offset, end - cursor));
        }
    }

    private static String digest(FileChannel channel, Probe probe, BooleanSupplier cancelled)
            throws IOException {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        }
        catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
        ByteBuffer buffer = ByteBuffer.allocate(65536);
        long cursor = 0;
        while (cursor < probe.size()) {
            checkCancelled(cancelled);
            buffer.clear().limit((int) Math.min(buffer.capacity(), probe.size() - cursor));
            int count = channel.read(buffer, probe.offset() + cursor);
            if (count <= 0) {
                throw new IOException("incomplete executable identity read");
            }
            digest.update(buffer.array(), 0, count);
            cursor += count;
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private static void artifact(StringBuilder out, String role, Path path, String sha256) {
        out.append(',').append(quote(role)).append(":{\"path\":").append(quote(path.toString()))
            .append(",\"sha256\":").append(quote(sha256)).append('}');
    }

    private static void requirePath(Path path) throws IOException {
        String value = path.toString();
        if (value.length() > 16384 || value.chars().anyMatch(character -> character < 32 || character == 127)) {
            throw new IOException("unsupported pathname for explicit GDB companion");
        }
    }

    private static String quote(String value) {
        StringBuilder out = new StringBuilder("\"");
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (character == '"' || character == '\\') {
                out.append('\\').append(character);
            }
            else if (character < 32 || character > 126) {
                out.append(String.format("\\u%04x", (int) character));
            }
            else {
                out.append(character);
            }
        }
        return out.append('"').toString();
    }

    private static void checkCancelled(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) {
            throw new CancellationException("GDB companion generation cancelled");
        }
    }
}
