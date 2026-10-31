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
            if (fields.length != 4 && fields.length != 5) throw new AssertionError("invalid observation");
            long entry = Long.parseLong(fields[1]);
            long symbolValue = fields.length == 5 ? Long.parseLong(fields[4]) : entry;
            long size = Long.parseLong(fields[2]);
            int index = Integer.parseInt(fields[3]);
            if (image.sections().isEmpty()) {
                // Independent test oracle: derive the writer's load allocation ordinal.
                index = 0;
                int ordinal = 0;
                for (var segment : image.segments()) {
                    if (segment.type != 1 || segment.memorySize == 0) continue;
                    ordinal++;
                    if ((segment.flags & 1) != 0 && entry >= segment.virtualAddress && size > 0 &&
                            Math.addExact(entry, size) <= Math.addExact(segment.virtualAddress, segment.fileSize)) {
                        if (index != 0) throw new AssertionError("ambiguous original code");
                        index = ordinal;
                    }
                }
                if (index == 0) throw new AssertionError("missing original code");
            }
            else {
                var section = image.sections().get(index);
                if (entry < section.address || size <= 0 || Math.addExact(entry, size) >
                        Math.addExact(section.address, section.size)) throw new AssertionError("out of section");
            }
            symbols.add(new ElfLocalFunctionSymbol(fields[0], symbolValue, size, index));
        }
        int expected = args.length == 5 ? Integer.parseInt(args[4]) : 2;
        if (expected < 2 || expected > 65536 || symbols.size() != expected) {
            throw new AssertionError("unexpected observation count");
        }
        new MatchedElfSidecarWriter().write(image, Path.of(args[3]), debug, symbols, () -> false);
        System.out.println("writer=" + MatchedElfSidecarWriter.class.getProtectionDomain().getCodeSource().getLocation());
        System.out.println("java=" + System.getProperty("java.version"));
        System.out.println("curated-alias-writer=PASS");
    }
}
