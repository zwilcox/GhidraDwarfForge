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
        if ((args.length < 4 || args.length > 6) || currentProgram != null ||
                (args.length >= 5 && !java.util.Set.of("controls", "raw", "raw-controls").contains(args[4])) ||
                (args.length == 6 && args[4].equals("controls"))) {
            throw new IllegalArgumentException("project-parent original output expected-module [controls|raw|raw-controls] [firmware-inputs]");
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
                if (args.length >= 5 && args[4].equals("raw-controls")) {
                    runScript("CheckRawFirmwareFailures.java", args.length == 6
                        ? new String[] {args[1], args[2], args[5]} : new String[] {args[1], args[2]});
                }
                else if (args.length == 5 && args[4].equals("controls")) {
                    runScript("CheckCortexMFailures.java", new String[] {args[1], args[2]});
                }
                else {
                    var options = new java.util.ArrayList<>(java.util.List.of(
                        "--packaged-natives", args.length >= 5 && args[4].equals("raw")
                            ? "--raw-firmware=cortex-m3" : "--target-profile=cortex-m3",
                        "--input=" + args[1], "--output=" + args[2]));
                    if (args.length == 6) options.add("--firmware-inputs=" + args[5]);
                    runScript("GhidraDwarfForge.java", options.toArray(String[]::new));
                }
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
