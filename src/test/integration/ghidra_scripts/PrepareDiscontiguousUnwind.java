// Curate an owned split-body fixture and observe its read-only export state.
// @category DWARF.Tests
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CommentType;
import java.nio.file.Files;
import java.nio.file.Path;

public class PrepareDiscontiguousUnwind extends GhidraScript {
    private Address symbol(String name) {
        var found = currentProgram.getSymbolTable().getGlobalSymbols(name);
        if (found.size() != 1) throw new AssertionError("missing/ambiguous symbol " + name);
        return found.getFirst().getAddress();
    }

    @Override protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) throw new IllegalArgumentException("prepare|rebase|partial|read observation.json");
        var function = getGlobalFunctions("cf_recurse").getFirst();
        Address first = symbol("cf_gap_first"), after = symbol("cf_gap_after");
        if (args[0].equals("prepare")) {
            var body = new AddressSet(function.getEntryPoint(), symbol("cf_body_end").previous());
            body.delete(first, after.previous());
            // The assembler declares one function across this branch. Ghidra
            // can instead discover its global branch target as a second function.
            // Curate that ownership only; supply no frame rules or stack facts.
            var manager = currentProgram.getFunctionManager();
            var overlaps = manager.getFunctionsOverlapping(body);
            var remove = new java.util.ArrayList<Address>();
            while (overlaps.hasNext()) {
                var other = overlaps.next();
                if (other.getEntryPoint().equals(function.getEntryPoint())) continue;
                if (!other.getEntryPoint().equals(after) || !body.contains(other.getBody())) {
                    throw new AssertionError("unexpected overlapping function " + other);
                }
                remove.add(other.getEntryPoint());
            }
            for (var address : remove) {
                manager.removeFunction(address);
                println("curated-interior-function=" + address);
            }
            clearListing(first, after.previous());
            getInstructionAt(symbol("cf_gap_jump")).setFlowOverride(ghidra.program.model.listing.FlowOverride.NONE);
            function.setBody(body);
            if (function.getBody().getNumAddressRanges() != 2) throw new AssertionError("expected split function body");
            currentProgram.getListing().setComment(function.getEntryPoint(), CommentType.PLATE, "DISCONTIGUOUS_UNWIND_ANALYST_COMMENT");
        }
        else if (args[0].equals("rebase")) {
            currentProgram.setImageBase(currentProgram.getImageBase().add(0x400000), true);
        }
        else if (args[0].equals("partial")) {
            var instruction = getInstructionAt(symbol("cf_gap_jump"));
            var body = new AddressSet(function.getBody());
            body.delete(instruction.getMaxAddress(), instruction.getMaxAddress());
            function.setBody(body);
            if (function.getBody().contains(instruction.getMaxAddress())) throw new AssertionError("partial instruction was silently restored");
        }
        else if (!args[0].equals("read")) throw new IllegalArgumentException("unknown mode");
        var out = new com.google.gson.JsonObject();
        out.addProperty("imageBase", currentProgram.getImageBase().toString());
        out.addProperty("entry", function.getEntryPoint().toString());
        out.addProperty("body", function.getBody().toString());
        out.addProperty("rangeCount", function.getBody().getNumAddressRanges());
        out.addProperty("plate", currentProgram.getListing().getComment(CommentType.PLATE, function.getEntryPoint()));
        Files.writeString(Path.of(args[1]), new com.google.gson.GsonBuilder().setPrettyPrinting().create().toJson(out) + "\n");
        println("discontiguous-program=" + args[0] + " PASS");
    }
}
