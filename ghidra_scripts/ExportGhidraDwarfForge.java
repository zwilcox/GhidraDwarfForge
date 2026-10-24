// Export the current program as a DWARF sidecar and synthetic C using packaged natives.
// Open a program, then run this script from Script Manager. Results appear in the Console.
// @category DWARF

import ghidra.app.script.GhidraScript;

public class ExportGhidraDwarfForge extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (isRunningHeadless()) {
            throw new IllegalStateException(
                "Run ExportGhidraDwarfForge from Script Manager; use the packaged wrapper headlessly");
        }
        runScript("GhidraDwarfForge.java", new String[] { "--packaged-natives" });
    }
}
