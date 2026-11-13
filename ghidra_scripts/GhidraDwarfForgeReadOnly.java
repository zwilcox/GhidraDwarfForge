// Export a saved program without opening its project for writing.
// @category DWARF
import java.nio.file.Path;
import java.util.Arrays;

import ghidra.app.script.GhidraScript;
import ghidra.framework.data.DefaultProjectData;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.ProjectLocator;
import ghidra.program.model.listing.Program;

public class GhidraDwarfForgeReadOnly extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (currentProgram != null || args.length < 4 || args[1].isBlank() ||
                args[1].contains("/") || args[1].contains("\\") || !args[2].startsWith("/")) {
            throw new IllegalArgumentException(
                "use an empty host project: project-directory project-name /program-path export-options...");
        }
        var locator = new ProjectLocator(Path.of(args[0]).toRealPath().toString(), args[1]);
        var project = new DefaultProjectData(locator, false, false);
        try {
            var file = project.getFile(args[2]);
            if (file == null || file.isInWritableProject()) {
                throw new IllegalArgumentException("saved program is absent or project is writable: " + args[2]);
            }
            var object = file.getReadOnlyDomainObject(this, DomainFile.DEFAULT_VERSION, monitor);
            try {
                if (!(object instanceof Program program)) {
                    throw new IllegalArgumentException("selected project file is not a program");
                }
                currentProgram = program;
                state.setCurrentProgram(program);
                runScript("GhidraDwarfForge.java", Arrays.copyOfRange(args, 3, args.length));
            }
            finally {
                currentProgram = null;
                state.setCurrentProgram(null);
                object.release(this);
            }
        }
        finally {
            project.close();
        }
    }
}
