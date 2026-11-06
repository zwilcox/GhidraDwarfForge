// A failed conditional recovery must preserve the original and previous outputs.
// @category DWARF.Tests
import ghidra.app.script.GhidraScript;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class RecoveredPointerRefusals extends GhidraScript {
    @Override protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 5) throw new IllegalArgumentException("libdwarf libdwarfp directory first:last extra-control");
        Path output = Path.of(args[2]).resolve("previous.dbg");
        List<Path> preserved = List.of(output, Path.of(output + ".c"), Path.of(output + ".unwind.json"));
        byte[] sentinel = "previous complete generation\n".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        for (Path path : preserved) Files.write(path, sentinel);
        String[] range = args[3].split(":");
        String shortRange = Long.toUnsignedString(Long.parseUnsignedLong(range[0], 16) + 1, 16) + ":" + range[1];
        var cases = new ArrayList<String[]>();
        cases.add(new String[] {});
        cases.add(new String[] {shortRange, "relocated-pointers"});
        if (args[4].equals("omit-pointers")) cases.add(new String[] {args[3]});
        else if (args[4].equals("unqualified-pointers")) cases.add(new String[] {args[3], "relocated-pointers"});
        else if (!args[4].equals("none")) throw new IllegalArgumentException("unknown refusal control");
        for (String[] condition : cases) {
            String[] options = {args[0], args[1], output.toString(), "none", "0", "none"};
            options = Arrays.copyOf(options, 6 + condition.length);
            System.arraycopy(condition, 0, options, 6, condition.length);
            boolean refused = false;
            try { runScript("ExportRecoveredFrames.java", options); }
            catch (AssertionError expected) {
                if (!expected.getMessage().startsWith("real import produced no frame proof:")) throw expected;
                refused = true;
            }
            if (!refused) throw new AssertionError("unsupported memory/call group produced a frame artifact");
            for (Path path : preserved) {
                if (!Arrays.equals(sentinel, Files.readAllBytes(path))) throw new AssertionError("refusal changed previous generation");
            }
            try (var files = Files.list(output.getParent())) {
                if (files.anyMatch(path -> path.getFileName().toString().startsWith("."))) throw new AssertionError("refusal leaked staging files");
            }
            println("pointer-refusal=PASS condition=" + Arrays.toString(condition));
        }
        println("pointer-refusal-controls=PASS count=" + cases.size());
    }
}
