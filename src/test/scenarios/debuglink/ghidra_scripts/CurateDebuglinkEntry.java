// Apply one analyst name to the private debuglink research project.
// @category DWARF.Tests

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.SourceType;

public class CurateDebuglinkEntry extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("expected fixture entry address");
        }
        var function = getFunctionAt(toAddr(args[0]));
        if (function == null) {
            throw new AssertionError("fixture entry function was not analyzed");
        }
        function.setName("debuglink_analyst_entry", SourceType.USER_DEFINED);
        analyzeChanges(currentProgram);
        println("debuglink-research-analyst-name=APPLIED");
    }
}
