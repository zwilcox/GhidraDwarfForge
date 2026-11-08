package ghidradwarfforge.elf;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CancellationException;

/** Compiler DWARF in the production matched writer; not Ghidra extraction. */
public final class GdbCompanionSmoke {
    private GdbCompanionSmoke() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 5) {
            throw new IllegalArgumentException("original reference source sidecar companion required");
        }
        Path original = Path.of(args[0]);
        Path reference = Path.of(args[1]);
        Path source = Path.of(args[2]);
        Path sidecar = Path.of(args[3]);
        Path companion = Path.of(args[4]);
        if (Files.exists(sidecar) || Files.exists(companion)) {
            throw new IllegalArgumentException("smoke output paths must be new");
        }
        ElfImage compiler = ElfImage.read(reference);
        Map<String, byte[]> sections = new LinkedHashMap<>();
        for (var section : compiler.sections()) {
            if (section.name.startsWith(".debug_")) {
                sections.put(section.name, compiler.sectionData(section));
            }
        }
        new MatchedElfSidecarWriter().write(original, sidecar, sections);
        String first = GdbCompanion.render(original, sidecar, source, sidecar, source, () -> false);
        String second = GdbCompanion.render(original, sidecar, source, sidecar, source, () -> false);
        if (!first.equals(second)) {
            throw new AssertionError("companion is not deterministic");
        }
        try {
            GdbCompanion.render(original, sidecar, source, sidecar, source, () -> true);
            throw new AssertionError("cancelled companion was generated");
        }
        catch (CancellationException expected) {
            // Cancellation produces no script or published output.
        }
        try {
            GdbCompanion.render(original, reference, source, sidecar, source, () -> false);
            throw new AssertionError("unmatched compiler reference accepted as Forge sidecar");
        }
        catch (java.io.IOException expected) {
            // A matching machine or copied DWARF alone is not a matched sidecar.
        }
        Files.writeString(companion, first, StandardCharsets.UTF_8);
        System.out.println("gdb-companion-smoke=PASS");
    }
}
