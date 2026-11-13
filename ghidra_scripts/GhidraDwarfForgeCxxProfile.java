// Inspect or transactionally configure explicit recovered C++ relationships.
// @category DWARF

import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidradwarfforge.GhidraCxxProfile;
import ghidradwarfforge.output.CxxSelection;
import java.nio.file.Path;
import java.util.List;

public class GhidraDwarfForgeCxxProfile extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (currentProgram == null) throw new IllegalStateException("Open the analyzed program first");
        String[] args = getScriptArgs();
        if (args.length > 2 || args.length == 0 && isRunningHeadless()) {
            throw new IllegalArgumentException("inspect [name-filter] | check selection.json | apply selection.json");
        }
        String mode = args.length == 0 ? askChoice("C++ relationships", "Action", List.of("inspect", "check", "apply"), "inspect") : args[0];
        var json = new GsonBuilder().disableHtmlEscaping().create();
        if (mode.equals("inspect")) {
            println("GhidraDwarfForge C++ inventory: " + json.toJson(GhidraCxxProfile.inspect(currentProgram, args.length == 2 ? args[1] : "", monitor)));
            return;
        }
        if (!mode.equals("check") && !mode.equals("apply")) throw new IllegalArgumentException("unknown C++ profile action");
        if (args.length != 2 && isRunningHeadless()) throw new IllegalArgumentException("selection.json is required");
        Path path = args.length == 2 ? Path.of(args[1]) : askFile("Select explicit C++ relationships", mode).toPath();
        var selected = CxxSelection.read(path, monitor::isCancelled);
        var result = GhidraCxxProfile.configure(currentProgram, selected, mode.equals("apply"), monitor);
        println("GhidraDwarfForge C++ selection: " + json.toJson(result));
        println(result.saved() ? "Relationships applied; save the program to retain them." :
            "Selection validated against the current program; configuration changes rolled back.");
    }
}
