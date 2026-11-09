// Invoke the installed exporter without opening the fixture's project writable.
// @category DWARF.Tests
import java.nio.file.Path;
import java.util.Objects;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.framework.data.DefaultProjectData;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.ProjectLocator;
import ghidra.program.model.listing.Program;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter;

public class ExportCortexMReadOnly extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 4 || currentProgram != null) {
            throw new IllegalArgumentException("project-parent original output expected-module");
        }
        Path expected = Path.of(args[3]).toRealPath();
        Path module = Application.getModuleRootDir("GhidraDwarfForge").getFile(false).toPath().toRealPath();
        Path jar = Path.of(MinimalDwarfSidecarExporter.class.getProtectionDomain()
            .getCodeSource().getLocation().toURI()).toRealPath();
        if (!module.equals(expected) || !jar.equals(module.resolve("lib/GhidraDwarfForge.jar").toRealPath())) {
            throw new AssertionError("wrong installed exporter provenance");
        }
        var project = new DefaultProjectData(new ProjectLocator(args[0], "CortexM"), false, false);
        try {
            var file = Objects.requireNonNull(project.getFile("/" + Path.of(args[1]).getFileName()));
            if (file.isInWritableProject()) throw new AssertionError("fixture project is writable");
            var program = (Program) file.getReadOnlyDomainObject(this, DomainFile.DEFAULT_VERSION, monitor);
            try {
                currentProgram = program;
                runScript("GhidraDwarfForge.java", new String[] {
                    "--packaged-natives", "--input=" + args[1], "--output=" + args[2]});
                println("cortex-m-read-only-export=PASS jar=" + jar);
            }
            finally {
                currentProgram = null;
                state.setCurrentProgram(null);
                program.release(this);
            }
        }
        finally {
            project.close();
        }
    }
}
