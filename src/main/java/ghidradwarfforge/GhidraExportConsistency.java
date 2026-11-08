package ghidradwarfforge;

import java.io.IOException;
import java.nio.file.Path;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

import ghidra.program.model.listing.Program;
import ghidradwarfforge.output.FileDigests;

/** Optimistic evidence checks, not a filesystem snapshot or a Ghidra modification lock. */
public final class GhidraExportConsistency {
    private final Program program;
    private final long modification;
    private final Path input;
    private final FileDigests.Result digest;

    private GhidraExportConsistency(Program program, long modification, Path input, FileDigests.Result digest) {
        this.program = program;
        this.modification = modification;
        this.input = input;
        this.digest = digest;
    }

    public static GhidraExportConsistency capture(Program program, Path input, BooleanSupplier cancelled) throws IOException {
        checkCancelled(cancelled);
        if (program.isClosed()) throw new IOException("Ghidra program is closed");
        long modification = program.getModificationNumber();
        Path original = input.toRealPath();
        var result = new GhidraExportConsistency(program, modification, original, FileDigests.read(original, cancelled));
        result.requireProgramUnchanged();
        checkCancelled(cancelled);
        return result;
    }

    public String inputSha256() { return digest.sha256(); }

    /** Run after extraction and immediately before publishing the staged generation. */
    public void requireUnchanged(BooleanSupplier cancelled) throws IOException {
        checkCancelled(cancelled);
        requireProgramUnchanged();
        if (!digest.equals(FileDigests.read(input, cancelled))) {
            throw new IOException("Original ELF changed during export: " + input);
        }
        requireProgramUnchanged();
        checkCancelled(cancelled);
    }

    private void requireProgramUnchanged() throws IOException {
        if (program.isClosed() || program.getModificationNumber() != modification) {
            throw new IOException("Ghidra program changed during export; retry with analysis and edits quiescent");
        }
    }

    private static void checkCancelled(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("export consistency check cancelled");
    }
}
