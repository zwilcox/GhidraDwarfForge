package ghidradwarfforge;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Protect saved project files and file aliases from export destinations. */
public final class GhidraProjectOutputProtection {
    private GhidraProjectOutputProtection() { }

    public static void requireSafeOutputs(Program program, List<Path> outputs, TaskMonitor monitor) throws Exception {
        var file = program.getDomainFile();
        if (file == null || file.getProjectLocator() == null) return;
        var locator = file.getProjectLocator();
        Path directory = locator.getProjectDir().toPath().toRealPath();
        var marker = ghidradwarfforge.output.FileSystemPaths.resolveLeaf(locator.getMarkerFile().toPath(), "project marker");
        var lock = ghidradwarfforge.output.FileSystemPaths.resolveLeaf(locator.getProjectLockFile().toPath(), "project lock");
        var existing = new ArrayList<Path>();
        for (Path output : outputs) {
            monitor.checkCancelled();
            Path path = ghidradwarfforge.output.FileSystemPaths.resolveLeaf(output, "export output");
            if (path.startsWith(directory)) {
                throw new IOException("export output is inside the saved project: " + path);
            }
            for (Path reserved : List.of(marker, lock)) {
                if (ghidradwarfforge.output.FileSystemPaths.aliases(path, reserved)) {
                    throw new IOException("export output aliases a saved project file: " + reserved);
                }
            }
            if (!Files.notExists(path)) existing.add(path);
        }
        if (existing.isEmpty()) return;
        // Do not follow directory symlinks recursively. Existing file symlinks
        // are still compared by identity, like hard links, by aliases().
        try (var files = Files.walk(directory)) {
            var iterator = files.iterator();
            while (iterator.hasNext()) {
                monitor.checkCancelled();
                Path path = iterator.next();
                if (Files.isRegularFile(path)) {
                    for (Path output : existing) {
                        if (ghidradwarfforge.output.FileSystemPaths.aliases(output, path)) {
                            throw new IOException("export output aliases a saved project file: " + path);
                        }
                    }
                }
            }
        }
    }

}
