package ghidradwarfforge.elf;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

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
        Map<Path, byte[]> protectedFiles = new LinkedHashMap<>();
        for (Path path : new Path[] {original, reference, source, sidecar}) {
            protectedFiles.put(path, Files.readAllBytes(path));
        }
        var checkpoints = new AtomicInteger();
        String counted = GdbCompanion.render(original, sidecar, source, sidecar, source, () -> {
            checkpoints.incrementAndGet();
            return false;
        });
        if (!first.equals(counted) || checkpoints.get() < 2) {
            throw new AssertionError("missing successful cancellation-check baseline");
        }
        for (int stop = 1; stop <= checkpoints.get(); stop++) {
            final int selected = stop;
            var observed = new AtomicInteger();
            try {
                GdbCompanion.render(original, sidecar, source, sidecar, source,
                    () -> observed.incrementAndGet() == selected);
                throw new AssertionError("companion ignored cancellation at checkpoint " + stop);
            }
            catch (CancellationException expected) {
                if (observed.get() != stop) throw new AssertionError("cancellation was not prompt");
            }
            unchanged(protectedFiles, companion);
        }
        for (char unsafe : new char[] {'\n', '\r', '\t', 127}) {
            for (boolean invalidSidecar : new boolean[] {true, false}) {
                Path invalid = sidecar.resolveSibling("unsafe" + unsafe + "name");
                try {
                    GdbCompanion.render(original, sidecar, source,
                        invalidSidecar ? invalid : sidecar, invalidSidecar ? source : invalid, () -> false);
                    throw new AssertionError("unsafe final pathname accepted");
                }
                catch (java.io.IOException expected) {
                    if (!expected.getMessage().contains("unsupported pathname")) throw expected;
                }
                if (Files.exists(invalid)) throw new AssertionError("invalid destination was created");
                unchanged(protectedFiles, companion);
            }
        }
        try {
            GdbCompanion.render(original, reference, source, sidecar, source, () -> false);
            throw new AssertionError("unmatched compiler reference accepted as Forge sidecar");
        }
        catch (java.io.IOException expected) {
            // A matching machine or copied DWARF alone is not a matched sidecar.
        }
        unchanged(protectedFiles, companion);
        if (!first.equals(GdbCompanion.render(original, sidecar, source, sidecar, source, () -> false))) {
            throw new AssertionError("failed attempts changed the successful retry");
        }
        Files.writeString(companion, first, StandardCharsets.UTF_8);
        System.out.println("gdb-companion-smoke=PASS cancellation-checkpoints=" + checkpoints.get() + " invalid-paths=8");
    }

    private static void unchanged(Map<Path, byte[]> protectedFiles, Path companion) throws Exception {
        for (var entry : protectedFiles.entrySet()) {
            if (!Arrays.equals(entry.getValue(), Files.readAllBytes(entry.getKey()))) {
                throw new AssertionError("companion attempt modified " + entry.getKey());
            }
        }
        if (Files.exists(companion)) throw new AssertionError("failed attempt published a companion");
    }
}
