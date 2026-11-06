// Recover ordinary call frames with an explicit policy and generation-bound evidence.
// @category DWARF

import ghidra.app.script.GhidraScript;
import java.util.ArrayList;
import java.util.List;

public class ExportGhidraDwarfForgeWithUnwind extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (isRunningHeadless()) throw new IllegalStateException("Use --synthesize-unwind with the headless wrapper");
        String choice = askChoice("Call-frame recovery", "Recover ordinary frames where instruction evidence permits",
            List.of("Off", "Strict", "Explicit memory conditions"), "Off");
        var options = new ArrayList<>(List.of("--packaged-natives"));
        switch (choice) {
            case "Off" -> options.add("--synthesize-unwind=off");
            case "Strict" -> options.add("--synthesize-unwind=strict");
            case "Explicit memory conditions" -> {
                options.add("--synthesize-unwind=conditioned");
                String ranges = askString("External stack condition",
                    "Original ELF hex first:last ranges, comma separated. You assert these never overlap live stack storage of the analyzed call groups or callers.");
                options.add("--unwind-stack-separation=" + ranges);
                String pointers = askChoice("External pointer condition",
                    "Assume qualified relocated pointers stay fixed after loading, with all stack-relative accesses disjoint from their slots?",
                    List.of("No", "Yes, record this condition"), "No");
                options.add("--unwind-relocated-pointers=" + (pointers.equals("No") ? "off" : "fixed"));
            }
            default -> throw new IllegalArgumentException("unknown call-frame recovery choice");
        }
        runScript("GhidraDwarfForge.java", options.toArray(String[]::new));
    }
}
