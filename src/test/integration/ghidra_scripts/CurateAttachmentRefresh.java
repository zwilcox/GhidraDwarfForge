import ghidra.app.script.GhidraScript;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SourceType;

/** Persist real analyst edits without changing the imported image identity. */
public class CurateAttachmentRefresh extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 4 || !(args[0].equals("anchor") || args[0].equals("edit") || args[0].equals("verify"))) {
            throw new IllegalArgumentException("supply anchor|edit|verify function-address original-path import-sha256");
        }
        // The importer stores the local FSRL path, including /C:/... on Windows,
        // rather than the native C:\... spelling supplied to analyzeHeadless.
        String expectedPath = FileSystemService.getInstance().getLocalFSRL(new java.io.File(args[2])).getPath();
        if (!currentProgram.getExecutablePath().equals(expectedPath) ||
                !currentProgram.getExecutableSHA256().equalsIgnoreCase(args[3])) {
            throw new IllegalStateException("saved import identity changed: path=" + currentProgram.getExecutablePath() +
                "; expected=" + expectedPath + "; sha256=" + currentProgram.getExecutableSHA256() +
                "; expected-sha256=" + args[3]);
        }
        var function = getFunctionAt(toAddr(args[1]));
        if (function == null) throw new IllegalStateException("missing fixture function");
        var category = new CategoryPath("/GhidraDwarfForgeFixture");
        if (args[0].equals("anchor")) {
            // Favorites are session state. Apply the analyst type to a genuine
            // saved variable so the next process has an explicit type root.
            // Its storage remains honestly unavailable.
            var type = (Structure) currentProgram.getDataTypeManager().getDataType(category, "fixture_state");
            function.addLocalVariable(new LocalVariableImpl("analyst_saved_state", 0, type,
                VariableStorage.UNASSIGNED_STORAGE, false, currentProgram, SourceType.USER_DEFINED),
                SourceType.USER_DEFINED);
            println("curated-refresh-program=PASS mode=anchor import-sha256=" + args[3]);
            return;
        }
        if (args[0].equals("edit")) {
            if (!function.getName().equals("recovered_add")) throw new IllegalStateException("unexpected old name");
            function.setName("curated_refresh_add", SourceType.USER_DEFINED);
            var type = (Structure) currentProgram.getDataTypeManager().getDataType(category, "fixture_state");
            type.setName("curated_refresh_state");
            type.getComponent(0).setFieldName("curated_refresh_member");
        }
        var type = (Structure) currentProgram.getDataTypeManager().getDataType(category, "curated_refresh_state");
        if (!function.getName().equals("curated_refresh_add") || type == null ||
                !type.getComponent(0).getFieldName().equals("curated_refresh_member")) {
            throw new IllegalStateException("analyst edits were not retained");
        }
        boolean applied = java.util.Arrays.stream(function.getLocalVariables()).anyMatch(variable ->
            variable.getName().equals("analyst_saved_state") && variable.getDataType().equals(type));
        if (!applied) throw new IllegalStateException("saved analyst variable type was lost");
        println("curated-refresh-program=PASS mode=" + args[0] + " import-sha256=" + args[3]);
    }
}
