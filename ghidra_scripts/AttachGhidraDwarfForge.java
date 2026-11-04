// Review and explicitly attach a validated sidecar using a separate helper process.
// Select an ATTACH or REFRESH request described in docs/ATTACHMENT-HELPER.md.
// @category DWARF

import ghidra.app.script.GhidraScript;
import ghidradwarfforge.output.AttachmentGui;

public class AttachGhidraDwarfForge extends GhidraScript {
    @Override
    protected void run() throws Exception {
        AttachmentGui.run(this, monitor, false);
    }
}
