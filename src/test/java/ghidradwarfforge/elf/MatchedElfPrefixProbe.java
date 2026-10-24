package ghidradwarfforge.elf;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;

/** Installed-JAR protocol for the independent retained-prefix oracle. */
public final class MatchedElfPrefixProbe {
    private MatchedElfPrefixProbe() {
    }

    public static void main(String[] arguments) throws Exception {
        boolean reject = arguments.length > 0 && arguments[0].equals("--expect-rejection");
        int start = reject ? 1 : 0;
        if (arguments.length <= start || (arguments.length - start) % 2 != 0) {
            throw new IllegalArgumentException("supply original/candidate pairs");
        }
        System.out.println("prefix-class-source=" + MatchedElfPrefix.class.getProtectionDomain()
            .getCodeSource().getLocation().toURI());
        System.out.println("elf-image-class-source=" + ElfImage.class.getProtectionDomain()
            .getCodeSource().getLocation().toURI());
        System.out.println("java-version=" + System.getProperty("java.version"));
        System.out.println("max-heap=" + Runtime.getRuntime().maxMemory());
        for (int index = start; index < arguments.length; index += 2) {
            try {
                var result = MatchedElfPrefix.compare(Path.of(arguments[index]), Path.of(arguments[index + 1]));
                if (reject) {
                    throw new AssertionError("malformed ELF returned an observation");
                }
                System.out.printf("prefix=%d status=%s original=%d candidate=%d extent=%d different=%s diagnostic=%s%n",
                    (index - start) / 2, result.status(), result.originalByteCount(), result.candidateByteCount(),
                    result.comparedExtent(), result.firstDifferentOffset().isPresent()
                        ? Long.toString(result.firstDifferentOffset().getAsLong()) : "-",
                    Base64.getEncoder().encodeToString(result.diagnostic().getBytes(StandardCharsets.UTF_8)));
            }
            catch (IOException failure) {
                if (!reject) {
                    throw failure;
                }
                if (failure.getMessage() == null || failure.getMessage().isBlank()) {
                    throw new AssertionError("rejection has no diagnostic", failure);
                }
                System.out.println("rejected=" + failure.getClass().getName() + " diagnostic=" +
                    Base64.getEncoder().encodeToString(failure.getMessage().getBytes(StandardCharsets.UTF_8)));
            }
        }
    }
}
