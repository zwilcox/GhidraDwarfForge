package ghidradwarfforge.elf;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;

/** Installed-JAR observation adapter for the independent GNU note oracle. */
public final class ElfBuildIdProbe {
    private ElfBuildIdProbe() {
    }

    public static void main(String[] arguments) throws Exception {
        System.out.println("build-id-class-source=" + ElfBuildId.class.getProtectionDomain()
            .getCodeSource().getLocation().toURI());
        System.out.println("elf-image-class-source=" + ElfImage.class.getProtectionDomain()
            .getCodeSource().getLocation().toURI());
        System.out.println("java-version=" + System.getProperty("java.version"));
        System.out.println("max-heap=" + Runtime.getRuntime().maxMemory());
        if (arguments.length == 2 && arguments[0].equals("--expect-rejection")) {
            try {
                ElfBuildId.read(Path.of(arguments[1]));
            }
            catch (IOException | IllegalArgumentException expected) {
                System.out.println("rejected=" + expected.getClass().getName());
                System.out.println("diagnostic-base64=" + Base64.getEncoder().encodeToString(
                    String.valueOf(expected.getMessage()).getBytes(StandardCharsets.UTF_8)));
                return;
            }
            throw new AssertionError("malformed note input was accepted");
        }
        if (arguments.length == 0 || arguments.length % 2 != 0) {
            throw new IllegalArgumentException("supply pairs of original/sidecar input paths");
        }
        var observations = new ArrayList<ElfBuildId.Observation>();
        for (int index = 0; index < arguments.length; index++) {
            var observed = ElfBuildId.read(Path.of(arguments[index]));
            observations.add(observed);
            System.out.printf("observation=%d hex=%s notes=%d%n", index,
                observed.hex().orElse("-"), observed.occurrences().size());
        }
        for (int index = 0; index < observations.size(); index += 2) {
            System.out.printf("relation=%d %s%n", index / 2,
                ElfBuildId.compare(observations.get(index), observations.get(index + 1)).name());
        }
    }
}
