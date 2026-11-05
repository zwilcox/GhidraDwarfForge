// Add two comments to a private project copy at independently observed native token addresses.
// @category DWARF.Tests
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.CommentType;
import ghidradwarfforge.GhidraFunctionSymbols;
import ghidradwarfforge.GhidraSyntheticSource;
import com.google.gson.GsonBuilder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.TreeMap;
import java.util.TreeSet;

public class SeedAnnotationTokenComments extends GhidraScript {
    @Override
    public void run() throws Exception {
        var functions = GhidraFunctionSymbols.extract(currentProgram, monitor, ignored -> { }, 0)
            .stream().filter(function -> function.name().equals("annotation_conflicts")).toList();
        if (functions.size() != 1) throw new AssertionError("missing conflict function");
        var source = GhidraSyntheticSource.decompile(currentProgram, functions, 0, monitor);
        var rows = new String(source.utf8(), StandardCharsets.UTF_8).split("\n", -1);
        var candidates = new TreeMap<Long, TreeSet<Integer>>();
        for (var function : source.functionTokens()) {
            for (var line : function.lines()) {
                for (long address : line.addresses()) {
                    candidates.computeIfAbsent(address, ignored -> new TreeSet<>()).add(line.line());
                }
            }
        }
        for (var entry : candidates.entrySet()) {
            monitor.checkCancelled();
            if (entry.getValue().size() != 1) continue;
            String text = rows[entry.getValue().first() - 1].strip();
            if (!text.startsWith("return ") && !text.contains(" = ")) continue;
            var address = toAddr(entry.getKey());
            var instruction = getInstructionAt(address);
            if (instruction == null || instruction.getLength() < 2) continue;
            var interior = address.add(1);
            var listing = currentProgram.getListing();
            if (listing.getComment(CommentType.EOL, address) != null ||
                    listing.getComment(CommentType.PRE, interior) != null) continue;
            listing.setComment(address, CommentType.EOL, "FORGE_TOKEN_POSITIVE:EOL λ */ exact token");
            listing.setComment(interior, CommentType.PRE, "FORGE_TOKEN_POSITIVE:PRE λ */ instruction interior");
            var result = new TreeMap<String, Object>();
            result.put("address", Long.toUnsignedString(address.getOffset(), 16));
            result.put("interior", Long.toUnsignedString(interior.getOffset(), 16));
            result.put("space", address.getAddressSpace().getName());
            result.put("nativeSourceLine", text);
            Files.writeString(Path.of(getScriptArgs()[0]), new GsonBuilder().setPrettyPrinting().create().toJson(result) + "\n");
            println("annotation-token-seed=PASS");
            return;
        }
        throw new AssertionError("no unique native token with unused comment categories");
    }
}
