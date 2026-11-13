// Run failure controls against a disposable read-only domain object.
// @category DWARF.Tests
import java.nio.file.Path;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.framework.data.DefaultProjectData;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.ProjectLocator;
import ghidra.program.model.listing.Program;

public class RunMmioControls extends GhidraScript {
    @Override protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (currentProgram != null || (args.length != 7 && args.length != 8) ||
                (args.length == 8 && !args[7].equals("raw"))) {
            throw new IllegalArgumentException("project-directory project-name /program input output module controls-directory [raw]");
        }
        Path expected = Path.of(args[5]).toRealPath();
        Path module = Application.getModuleRootDir("GhidraDwarfForge").getFile(false).toPath().toRealPath();
        Path jar = Path.of(ghidradwarfforge.GhidraMmioProfile.class.getProtectionDomain()
            .getCodeSource().getLocation().toURI()).toRealPath();
        if (!module.equals(expected) || !jar.equals(module.resolve("lib/GhidraDwarfForge.jar").toRealPath())) {
            throw new AssertionError("wrong installed MMIO implementation");
        }
        var project = new DefaultProjectData(new ProjectLocator(args[0], args[1]), false, false);
        try {
            var file = project.getFile(args[2]);
            if (file == null || file.isInWritableProject()) throw new AssertionError("fixture must be saved and read-only");
            var program = (Program) file.getReadOnlyDomainObject(this, DomainFile.DEFAULT_VERSION, monitor);
            try {
                currentProgram = program;
                state.setCurrentProgram(program);
                runScript("CheckMmioFailures.java", args.length == 8
                    ? new String[] {args[3], args[4], args[6], "raw"}
                    : new String[] {args[3], args[4], args[6]});
            }
            finally {
                currentProgram = null;
                state.setCurrentProgram(null);
                program.release(this);
            }
        }
        finally { project.close(); }
    }
}
