package ghidradwarfforge;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Protect saved project files and file aliases from optional output generations. */
public final class GhidraProjectOutputProtection {
    private GhidraProjectOutputProtection() { }

    public static void requireSafeOutputs(Program program, List<Path> outputs, TaskMonitor monitor) throws Exception {
        var file = program.getDomainFile();
        if (file == null || file.getProjectLocator() == null) return;
        var locator = file.getProjectLocator();
        Path directory = locator.getProjectDir().toPath().toRealPath();
        var resolved = new ArrayList<Path>();
        for (Path output : outputs) {
            monitor.checkCancelled();
            Path path = ghidradwarfforge.output.FileSystemPaths.resolveLeaf(output, "export output");
            if (path.startsWith(directory)) {
                throw new IOException("export output is inside the saved project: " + path);
            }
            resolved.add(path);
        }
        var protectedPaths = new ArrayList<Path>();
        protectedPaths.add(locator.getMarkerFile().toPath());
        protectedPaths.add(locator.getProjectLockFile().toPath());
        // Do not follow directory symlinks recursively. Existing file symlinks
        // are still compared by identity, like hard links, by aliases().
        try (var files = Files.walk(directory)) {
            var iterator = files.iterator();
            while (iterator.hasNext()) {
                monitor.checkCancelled();
                Path path = iterator.next();
                if (Files.isRegularFile(path)) protectedPaths.add(path);
            }
        }
        for (Path path : protectedPaths) {
            monitor.checkCancelled();
            Path protectedPath = ghidradwarfforge.output.FileSystemPaths.resolveLeaf(path, "saved project file");
            for (Path output : resolved) {
                if (ghidradwarfforge.output.FileSystemPaths.aliases(output, protectedPath)) {
                    throw new IOException("export output aliases a saved project file: " + path);
                }
            }
        }
    }

}
