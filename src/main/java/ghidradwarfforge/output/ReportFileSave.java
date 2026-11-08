package ghidradwarfforge.output;

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/** Atomically publishes an explicitly selected new report; never replaces existing paths. */
public final class ReportFileSave {
    private ReportFileSave() { }

    public static Path writeNew(Path selected, String report, BooleanSupplier cancelled) throws IOException {
        check(cancelled);
        Path path = FileSystemPaths.resolveLeaf(selected, "coverage report");
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) throw new IOException("Choose a new report filename; selected path already exists: " + path);
        Path stage = Files.createTempFile(path.getParent(), ".forge-report-", ".staged");
        try {
            try (var writer = new OutputStreamWriter(Files.newOutputStream(stage), StandardCharsets.UTF_8)) {
                for (int offset = 0; offset < report.length(); offset += 8192) {
                    check(cancelled);
                    writer.write(report, offset, Math.min(8192, report.length() - offset));
                }
            }
            check(cancelled);
            // Atomic create-if-absent on the same filesystem. A racing existing
            // file/symlink/hardlink is never replaced, including executable aliases.
            Files.createLink(path, stage);
            return path;
        }
        finally { Files.deleteIfExists(stage); }
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("report save cancelled");
    }
}
