// Export the current program to a fresh pair and prepare an explicit attachment or refresh.
// The executable changes only after a separate review, confirmation and live validation.
// @category DWARF

import ghidra.app.script.GhidraScript;
import ghidradwarfforge.output.AttachmentGui;

public class ExportAndAttachGhidraDwarfForge extends GhidraScript {
    @Override
    protected void run() throws Exception {
        AttachmentGui.prepare(this, monitor);
    }
}
