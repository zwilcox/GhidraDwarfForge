// Export the current program with opt-in zlib-compressed ELF debug sections.
// Synthetic C and default output names are unchanged; tiny sections may stay plain.
// @category DWARF

import ghidra.app.script.GhidraScript;

public class ExportCompressedGhidraDwarfForge extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (isRunningHeadless()) {
            throw new IllegalStateException(
                "Run ExportCompressedGhidraDwarfForge from Script Manager; use the packaged wrapper headlessly");
        }
        runScript("GhidraDwarfForge.java", new String[] {
            "--packaged-natives", "--compress-debug-sections=zlib" });
    }
}
