package ghidradwarfforge.elf;

import com.google.gson.JsonParser;
import ghidradwarfforge.output.FileDigests;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;

/** Compiler-owned evidence drives the production writer; not Ghidra binding admission. */
public final class VtablePackagingProbe {
    public static void main(String[] args) throws Exception {
        if (args.length != 4) throw new IllegalArgumentException("runtime debug-reference symbols.json output");
        Path input = Path.of(args[0]), debug = Path.of(args[1]), model = Path.of(args[2]), output = Path.of(args[3]);
        if (Files.exists(output)) throw new IllegalArgumentException("output must be new");
        String originalHash = FileDigests.read(input).sha256();
        var original = ElfImage.read(input);
        var reference = ElfImage.read(debug);
        if (original.machine() != reference.machine() || original.is64Bit() != reference.is64Bit() ||
                original.byteOrder() != reference.byteOrder()) throw new AssertionError("reference identity differs");
        var sections = new LinkedHashMap<String, byte[]>();
        for (var section : reference.sections()) {
            if (section.name.startsWith(".debug_")) sections.put(section.name, reference.sectionData(section));
        }
        var symbols = new ArrayList<ElfLocalObjectSymbol>();
        for (var value : JsonParser.parseString(Files.readString(model)).getAsJsonArray()) {
            var row = value.getAsJsonObject();
            var matches = original.sections().stream().filter(s -> s.name.equals(row.get("section").getAsString())).toList();
            if (matches.size() != 1) throw new AssertionError("missing or ambiguous original allocation");
            var section = matches.getFirst();
            if (section.address != row.get("sectionAddress").getAsLong()) throw new AssertionError("allocation moved");
            symbols.add(new ElfLocalObjectSymbol(row.get("name").getAsString(), row.get("address").getAsLong(),
                row.get("size").getAsLong(), original.sections().indexOf(section)));
        }
        if (symbols.isEmpty()) throw new AssertionError("missing compiler vtable evidence");
        var writer = new MatchedElfSidecarWriter();
        writer.write(original, output, sections, symbols, () -> false);
        var result = ElfImage.read(output);
        for (var section : original.sections()) {
            if (section.type == 11 || section.name.equals(".dynstr") ||
                    section.type == 0x6fffffffL || section.type == 0x6ffffffdL || section.type == 0x6ffffffeL) {
                if (!java.util.Arrays.equals(original.sectionData(section),
                        result.sectionData(result.sections().get(section.originalIndex)))) {
                    throw new AssertionError("original dynamic metadata changed: " + section.name);
                }
            }
        }
        Path repeat = output.resolveSibling(output.getFileName() + ".repeat");
        if (Files.exists(repeat)) throw new IllegalArgumentException("repeat output must be new");
        writer.write(original, repeat, sections, symbols, () -> false);
        if (Files.mismatch(output, repeat) != -1 || !FileDigests.read(input).sha256().equals(originalHash)) {
            throw new AssertionError("writer changed original or repeated output");
        }
        Files.delete(repeat);
        System.out.println("vtable-packaging=PASS objects=" + symbols.size());
    }
}
