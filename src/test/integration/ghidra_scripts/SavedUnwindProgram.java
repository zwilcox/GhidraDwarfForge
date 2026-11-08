// Prepare/read an owned saved fixture without exporting or changing original bytes.
// @category DWARF.Tests
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.CommentType;
import java.nio.file.Files;
import java.nio.file.Path;

public class SavedUnwindProgram extends GhidraScript {
    @Override protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2 || (!args[0].equals("setup") && !args[0].equals("read"))) {
            throw new IllegalArgumentException("setup|read observation.json");
        }
        if (args[0].equals("setup")) {
            currentProgram.setImageBase(currentProgram.getImageBase().add(0x400000), true);
            var function = getGlobalFunctions("cf_recurse").getFirst();
            currentProgram.getListing().setComment(function.getEntryPoint(), CommentType.PLATE, "SAVED_UNWIND_ANALYST_COMMENT λ */ original retained");
        }
        var out = new com.google.gson.JsonObject();
        out.addProperty("imageBase", currentProgram.getImageBase().toString());
        out.addProperty("imageBaseOffset", Long.toUnsignedString(currentProgram.getImageBase().getOffset(), 16));
        out.addProperty("originalImageBase", Long.toUnsignedString(ghidra.app.util.opinion.ElfLoader.getElfOriginalImageBase(currentProgram), 16));
        out.addProperty("executablePath", currentProgram.getExecutablePath());
        out.addProperty("importedSha256", currentProgram.getExecutableSHA256());
        var functions = new com.google.gson.JsonArray();
        for (var iterator = currentProgram.getFunctionManager().getFunctions(true); iterator.hasNext();) {
            var function = iterator.next();
            var entry = new com.google.gson.JsonObject();
            entry.addProperty("entry", function.getEntryPoint().toString());
            entry.addProperty("name", function.getName());
            entry.addProperty("body", function.getBody().toString());
            entry.addProperty("plate", currentProgram.getListing().getComment(CommentType.PLATE, function.getEntryPoint()));
            functions.add(entry);
        }
        out.add("functions", functions);
        Files.writeString(Path.of(args[1]), new com.google.gson.GsonBuilder().setPrettyPrinting().serializeNulls().create().toJson(out) + "\n");
        println("saved-unwind-program=" + args[0] + " PASS");
    }
}
