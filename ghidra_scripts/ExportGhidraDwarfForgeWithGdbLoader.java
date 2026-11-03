// Export the current program with an optional, explicitly invoked GDB loader.
// Produces <binary>.dbg, <binary>.dbg.c and <binary>.dbg.gdb.py together.
// @category DWARF

import ghidra.app.script.GhidraScript;

public class ExportGhidraDwarfForgeWithGdbLoader extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (isRunningHeadless()) {
            throw new IllegalStateException(
                "Run this script from Script Manager; use --gdb-loader with the headless wrapper");
        }
        runScript("GhidraDwarfForge.java", new String[] { "--packaged-natives", "--gdb-loader" });
    }
}
