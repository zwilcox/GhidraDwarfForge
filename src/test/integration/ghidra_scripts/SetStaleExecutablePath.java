// Simulates a moved/deleted original executable while retaining the imported program.
// @category DWARF.Tests

import ghidra.app.script.GhidraScript;

public class SetStaleExecutablePath extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 1 || arguments[0].isBlank()) {
            throw new IllegalArgumentException(
                "usage: SetStaleExecutablePath <missing-path>");
        }
        currentProgram.setExecutablePath(arguments[0]);
        println("Set stale fixture executable path to " + arguments[0]);
    }
}
