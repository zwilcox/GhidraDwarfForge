// Export optional deterministic source parts, preserving whole recovered functions.
// The ordinary ExportGhidraDwarfForge script keeps its single-source-file default.
// @category DWARF

import ghidra.app.script.GhidraScript;

public class ExportGhidraDwarfForgeMultiFile extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (isRunningHeadless()) {
            throw new IllegalStateException("Use --source-lines with the packaged headless wrapper");
        }
        String target = askString("Multi-file synthetic source",
            "Target lines per source file (whole functions stay together)", "1000");
        runScript("GhidraDwarfForge.java", new String[] {"--packaged-natives", "--source-lines=" + target});
    }
}
