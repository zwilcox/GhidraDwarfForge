// Prepare analyst edits before the imported program is saved.
// @category DWARF.Tests
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.SourceType;

public class PrepareProjectPreservation extends GhidraScript {
    @Override
    protected void run() throws Exception {
        var functions = currentProgram.getFunctionManager().getFunctions(true);
        if (!functions.hasNext()) throw new IllegalStateException("fixture has no function");
        var function = functions.next();
        function.setName("preserved_entry", SourceType.USER_DEFINED);
        function.setComment("Analyst note retained across read-only exports.");
        currentProgram.getOptions("Forge preservation fixture").setString("analyst", "saved knowledge");
        println("SAVED_PROJECT_PREPARED=PASS");
    }
}
