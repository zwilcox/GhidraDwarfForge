package ghidradwarfforge.elf;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/** Builds matched debug sidecars from program-header-only ELF fixtures. */
public final class SectionlessSidecarSmoke {
    private static final long SHT_RELA = 4;
    private static final long SHT_REL = 9;
    private static final String[] TARGETS = {
        "x86_64", "aarch64", "arm32", "mips32be", "mips32le"
    };
    private record Variant(String referenceName, String inputName, String outputName,
        boolean expectNoInputSections) {
    }
    private static final Variant[] VARIANTS = {
        new Variant("semantic.exec.reference", "semantic.exec.stripped",
            "semantic.exec.forge-container.dbg", false),
        new Variant("semantic.exec.reference", "semantic.exec.no-sections.stripped",
            "semantic.exec.no-sections.forge-container.dbg", true),
        new Variant("semantic.pie.reference", "semantic.pie.stripped",
            "semantic.pie.forge-container.dbg", false)
    };

    private SectionlessSidecarSmoke() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            throw new IllegalArgumentException(
                "usage: SectionlessSidecarSmoke <fixture-root> [target ...]");
        }
        Path fixtureRoot = Path.of(args[0]).toAbsolutePath().normalize();
        MatchedElfSidecarWriter writer = new MatchedElfSidecarWriter();
        String[] selectedTargets = args.length == 1 ? TARGETS :
            Arrays.copyOfRange(args, 1, args.length);
        for (String target : selectedTargets) {
            Path directory = fixtureRoot.resolve(target);
            for (Variant variant : VARIANTS) {
                Path reference = directory.resolve(variant.referenceName());
                Path input = directory.resolve(variant.inputName());
                Path output = directory.resolve(variant.outputName());
                byte[] originalHash = sha256(input);

                ElfImage referenceImage = ElfImage.read(reference);
                Map<String, byte[]> debugSections = new LinkedHashMap<>();
                for (ElfImage.Section section : referenceImage.sections()) {
                    if (section.name().startsWith(".debug_")) {
                        debugSections.put(section.name(), referenceImage.sectionData(section));
                    }
                }
                if (!debugSections.containsKey(".debug_info") ||
                    !debugSections.containsKey(".debug_abbrev")) {
                    throw new IllegalStateException("reference lacks required DWARF sections");
                }

                ElfImage inputImage = ElfImage.read(input);
                if (variant.expectNoInputSections() != inputImage.sections().isEmpty()) {
                    throw new IllegalStateException("unexpected input section-table state");
                }
                writer.write(input, output, debugSections);
                if (!Arrays.equals(originalHash, sha256(input))) {
                    throw new IllegalStateException("writer modified original input");
                }

                ElfImage result = ElfImage.read(output);
                if (result.sections().isEmpty() || result.machine() != inputImage.machine() ||
                    result.type() != inputImage.type() || result.flags() != inputImage.flags() ||
                    result.is64Bit() != inputImage.is64Bit() ||
                    result.byteOrder() != inputImage.byteOrder()) {
                    throw new IllegalStateException("sidecar target identity mismatch for " + target);
                }
                if (result.sections().stream().anyMatch(section ->
                        section.type == SHT_REL || section.type == SHT_RELA)) {
                    throw new IllegalStateException(
                        "matched sidecar retained an unresolved relocation section");
                }
                for (Map.Entry<String, byte[]> expected : debugSections.entrySet()) {
                    ElfImage.Section actual = result.sections().stream()
                    .filter(section -> expected.getKey().equals(section.name()))
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException(
                        "missing output section " + expected.getKey()));
                    if (!Arrays.equals(expected.getValue(), result.sectionData(actual))) {
                        throw new IllegalStateException("section data mismatch " + expected.getKey());
                    }
                }
                System.out.printf(
                    "target=%s input=%s class=%s endian=%s machine=%d sections=%d%n",
                    target, variant.inputName(), result.is64Bit() ? "ELF64" : "ELF32",
                    result.byteOrder(), result.machine(), result.sections().size());
            }
        }
        System.out.println("sectionless-sidecar-smoke=PASS");
    }

    private static byte[] sha256(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (var input = Files.newInputStream(path)) {
            byte[] buffer = new byte[64 * 1024];
            for (int count; (count = input.read(buffer)) != -1;) {
                digest.update(buffer, 0, count);
            }
        }
        return digest.digest();
    }
}
