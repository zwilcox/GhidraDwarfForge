package ghidradwarfforge.elf;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;

/** Research only: give the unchanged packaged writer load-backed alias observations. */
public class SectionlessSymbolProbe {
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
            int index = 0;
            int ordinal = 0;
            for (var segment : image.segments()) {
                if (segment.type != 1 || segment.memorySize == 0) continue;
                ordinal++;
                if ((segment.flags & 1) != 0 && entry >= segment.virtualAddress &&
                        size > 0 && Math.addExact(entry, size) <=
                        Math.addExact(segment.virtualAddress, segment.fileSize)) {
                    if (index != 0) throw new AssertionError("ambiguous original code");
                    index = ordinal;
                }
            }
            if (index == 0) throw new AssertionError("missing original code");
            symbols.add(new ElfLocalFunctionSymbol(fields[0], entry, size, index));
        }
        if (symbols.size() != 2) throw new AssertionError("two observations required");
        new MatchedElfSidecarWriter().write(image, Path.of(args[3]), debug, symbols, () -> false);
        System.out.println("writer=" + MatchedElfSidecarWriter.class.getProtectionDomain().getCodeSource().getLocation());
        System.out.println("java=" + System.getProperty("java.version"));
        System.out.println("curated-alias-writer=PASS");
    }
}
