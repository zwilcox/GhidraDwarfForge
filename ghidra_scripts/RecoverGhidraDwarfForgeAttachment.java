// Review explicit saved recovery selections and restore through a separate helper.
// Retain the original/previous images and transaction receipts until recovery completes.
// @category DWARF

import ghidra.app.script.GhidraScript;
import ghidradwarfforge.output.AttachmentGui;

public class RecoverGhidraDwarfForgeAttachment extends GhidraScript {
    @Override
    protected void run() throws Exception {
        AttachmentGui.run(this, monitor, true);
    }
}
