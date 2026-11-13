package ghidradwarfforge.firmware;

import com.google.gson.stream.JsonWriter;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.file.Path;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Map;
import java.util.TreeMap;

import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.output.FileDigests;
import ghidradwarfforge.output.FirmwareInputs;
import ghidradwarfforge.firmware.GhidraFirmwareMemoryMap.BoundInput;

/** Explicit firmware input selection, live-analysis binding and generation provenance. */
public final class GhidraFirmwareSession implements AutoCloseable {
    private record Analysis(String fileId, String project, String pathname, int version, long savedModified,
            long programId, long modification, boolean changed) {
        static Analysis capture(Program program) {
            var file = program.getDomainFile();
            // Read-only objects use DomainFileProxy: it has no parent folder, but
            // retains the saved file ID, project locator, pathname and revision.
            if (file == null || file.getProjectLocator() == null || file.getFileID() == null) {
                throw new IllegalArgumentException("raw firmware export requires a saved Ghidra program identity");
            }
            return new Analysis(file.getFileID(), file.getProjectLocator().toString(), file.getPathname(), file.getVersion(),
                file.getLastModifiedTime(), program.getUniqueProgramID(), program.getModificationNumber(),
                program.isChanged());
        }
    }

    private final Program program;
    private final Analysis analysis;
    private final FirmwareExportImage image;
    private final Map<String, Path> inputs;
    private final Map<String, BoundInput> bindings;
    private final Path selection;
    private final FileDigests.Result selectionDigest;

    private GhidraFirmwareSession(Program program, Analysis analysis, FirmwareExportImage image,
            Map<String, Path> inputs, Map<String, BoundInput> bindings,
            Path selection, FileDigests.Result selectionDigest) {
        this.program = program;
        this.analysis = analysis;
        this.image = image;
        this.inputs = Map.copyOf(inputs);
        this.bindings = Map.copyOf(bindings);
        this.selection = selection;
        this.selectionDigest = selectionDigest;
    }

    public static GhidraFirmwareSession open(Program program, FirmwareTarget target,
            Path primary, Path selection, TaskMonitor monitor) throws Exception {
        monitor.checkCancelled();
        var analysis = Analysis.capture(program);
        var fileBytes = program.getMemory().getAllFileBytes();
        var bound = new ArrayList<BoundInput>();
        FileDigests.Result selectionDigest = null;
        if (selection == null) {
            if (fileBytes.size() != 1) {
                throw new IllegalArgumentException("raw firmware with multiple FileBytes requires --firmware-inputs=<JSON>");
            }
            bound.add(new BoundInput("input", primary.toRealPath(), fileBytes.getFirst()));
        }
        else {
            selection = selection.toRealPath();
            selectionDigest = FileDigests.read(selection, monitor::isCancelled);
            for (var row : FirmwareInputs.read(selection, monitor::isCancelled).inputs()) {
                monitor.checkCancelled();
                if (row.fileBytesIndex() >= fileBytes.size()) {
                    throw new IllegalArgumentException("firmware FileBytes index is outside the current inventory");
                }
                Path path = Path.of(row.path());
                if (!path.isAbsolute()) path = selection.getParent().resolve(path);
                bound.add(new BoundInput(row.id(), path.toRealPath(), fileBytes.get(row.fileBytesIndex())));
            }
        }
        var paths = new TreeMap<String, Path>();
        var byId = new TreeMap<String, BoundInput>();
        for (var input : bound) {
            paths.put(input.id(), input.path());
            byId.put(input.id(), input);
        }
        if (!paths.containsValue(primary.toRealPath())) {
            throw new IllegalArgumentException("primary input is absent from firmware input bindings");
        }
        var map = GhidraFirmwareMemoryMap.capture(program, target, bound, monitor);
        var image = FirmwareExportImage.open(target, map, paths, monitor::isCancelled);
        var session = new GhidraFirmwareSession(program, analysis, image, paths, byId, selection, selectionDigest);
        try {
            session.requireUnchanged(monitor);
            return session;
        }
        catch (Exception | Error failure) {
            try { session.close(); }
            catch (IOException cleanup) { failure.addSuppressed(cleanup); }
            throw failure;
        }
    }

    public FirmwareExportImage image() { return image; }

    public java.util.List<Path> protectedInputs() {
        var paths = new ArrayList<>(inputs.values());
        if (selection != null) paths.add(selection);
        return java.util.List.copyOf(paths);
    }

    /** Also protect the saved analysis from a deliberately colliding output path. */
    public void requireSafeOutputs(java.util.List<Path> outputs, TaskMonitor monitor) throws Exception {
        ghidradwarfforge.GhidraProjectOutputProtection.requireSafeOutputs(program, outputs, monitor);
    }

    public void requireUnchanged(TaskMonitor monitor) throws IOException, CancelledException {
        monitor.checkCancelled();
        if (program.isClosed() || !analysis.equals(Analysis.capture(program))) {
            throw new IOException("saved analysis identity or current program state changed during firmware export");
        }
        image.requireInputsUnchanged(monitor::isCancelled);
        if (selection != null && !selectionDigest.equals(FileDigests.read(selection, monitor::isCancelled))) {
            throw new IOException("firmware input selection changed during export");
        }
    }

    /** Deterministic manifest. Analysis identity/revision is not claimed as a database checksum. */
    public String manifest(Path output, String outputSha256, Path source, String sourceSha256,
            TaskMonitor monitor) throws Exception {
        requireUnchanged(monitor);
        for (String hash : java.util.List.of(outputSha256, sourceSha256)) {
            if (!hash.matches("[0-9a-f]{64}")) throw new IllegalArgumentException("invalid firmware artifact digest");
        }
        var text = new StringWriter();
        try (var json = new JsonWriter(text)) {
            json.setIndent("    ");
            json.beginObject().name("schema").value(1).name("kind").value("synthetic-firmware-debug-container");
            var target = image.target();
            json.name("target").beginObject().name("profile").value(target.profile())
                .name("architecture").value(target.architecture()).name("abi").value(target.abi())
                .name("addressBits").value(target.addressBits()).name("pointerBits").value(target.pointerBits())
                .name("byteOrder").value(target.byteOrder().toString()).name("instructionMode").value(target.instructionMode())
                .name("languageId").value(target.languageId()).name("compilerSpecId").value(target.compilerSpecId())
                .name("elfMachine").value(target.machine()).name("elfFlags").value(target.elfFlags()).endObject();
            json.name("analysis").beginObject().name("binding").value("saved-file identity and observed revision; not a database checksum")
                .name("savedFileId").value(analysis.fileId()).name("project").value(analysis.project())
                .name("pathname").value(analysis.pathname())
                .name("version").value(analysis.version()).name("savedModifiedMillis").value(analysis.savedModified())
                .name("programId").value(Long.toUnsignedString(analysis.programId(), 16))
                .name("modificationNumber").value(analysis.modification()).name("hasUnsavedChanges").value(analysis.changed())
                .endObject();
            json.name("addressPolicy").value("fixed runtime addresses from current Ghidra memory map; no implicit load bias");
            json.name("inputs").beginArray();
            for (var input : image.memoryMap().inputs()) {
                monitor.checkCancelled();
                var bytes = bindings.get(input.id()).fileBytes();
                json.beginObject().name("id").value(input.id()).name("path").value(inputs.get(input.id()).toString())
                    .name("size").value(input.size()).name("sha256").value(input.sha256())
                    .name("ghidraFileBytesOffset").value(bytes.getFileOffset()).name("ghidraFileBytesSize").value(bytes.getSize())
                    .endObject();
            }
            json.endArray().name("regions").beginArray();
            int section = 0;
            for (var region : image.memoryMap().regions()) {
                monitor.checkCancelled();
                json.beginObject().name("name").value(region.name()).name("section").value(".forge.region." + section++)
                    .name("address").value("0x" + Long.toHexString(region.address())).name("size").value(region.length())
                    .name("read").value(region.read()).name("write").value(region.write()).name("execute").value(region.execute())
                    .name("storage").value(region.storage().name()).name("fileSpans").beginArray();
                for (var span : region.spans()) {
                    monitor.checkCancelled();
                    json.beginObject().name("regionOffset").value(span.regionOffset()).name("size").value(span.length())
                        .name("inputId").value(span.inputId()).name("fileOffset").value(span.fileOffset()).endObject();
                }
                json.endArray().endObject();
            }
            json.endArray().name("artifacts").beginObject().name("sidecar").value(output.toString())
                .name("sidecarSha256").value(outputSha256).name("source").value(source.toString())
                .name("sourceSha256").value(sourceSha256).endObject().endObject();
        }
        return text + "\n";
    }

    @Override
    public void close() throws IOException { image.close(); }
}
