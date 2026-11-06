// Choose optional assembly and p-code context for incomplete synthetic source.
// @category DWARF

import ghidra.app.script.GhidraScript;
import java.util.List;

public class ExportGhidraDwarfForgeWithContext extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (isRunningHeadless()) {
            throw new IllegalStateException("Use --source-context with the packaged headless wrapper");
        }
        String choice = askChoice("Source context", "Instruction context for incomplete synthetic source",
            List.of("Off", "Assembly", "P-code", "Both"), "Off");
        String mode = switch (choice) {
            case "Off" -> "off";
            case "Assembly" -> "assembly";
            case "P-code" -> "pcode";
            case "Both" -> "both";
            default -> throw new IllegalArgumentException("unknown source context choice");
        };
        runScript("GhidraDwarfForge.java", new String[] {"--packaged-natives", "--source-context=" + mode});
    }
}
