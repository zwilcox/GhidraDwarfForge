package ghidradwarfforge.elf;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;

/** Isolated consumer experiment using the unchanged packaged ELF writer. */
public class LocalSymbolMergeProbe {
    public static void main(String[] args) throws Exception {
        if (Runtime.version().feature() != 21) throw new AssertionError("actual Java 21 required");
        var image = ElfImage.read(Path.of(args[0]));
        var baseline = ElfImage.read(Path.of(args[1]));
        var debug = new LinkedHashMap<String, byte[]>();
        for (var section : baseline.sections()) {
            if (section.name.startsWith(".debug_")) debug.put(section.name, baseline.sectionData(section));
        }
        var symbols = new ArrayList<ElfLocalFunctionSymbol>();
        for (String line : Files.readAllLines(Path.of(args[2]))) {
            String[] fields = line.split("\\t");
            if (fields.length != 4) throw new AssertionError("invalid observation");
            long entry = Long.parseLong(fields[1]);
            long size = Long.parseLong(fields[2]);
            int index = Integer.parseInt(fields[3]);
            var section = image.sections().get(index);
            if (entry < section.address || size <= 0 || Math.addExact(entry, size) >
                    Math.addExact(section.address, section.size)) throw new AssertionError("out of section");
            symbols.add(new ElfLocalFunctionSymbol(fields[0], entry, size, index));
        }
        if (symbols.size() != 2) throw new AssertionError("two observations required");
        new MatchedElfSidecarWriter().write(image, Path.of(args[3]), debug, symbols, () -> false);
        System.out.println("writer=" + MatchedElfSidecarWriter.class.getProtectionDomain().getCodeSource().getLocation());
        System.out.println("java=" + System.getProperty("java.version"));
        System.out.println("curated-alias-writer=PASS");
    }
}
