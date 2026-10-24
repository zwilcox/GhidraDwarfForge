package ghidradwarfforge.elf;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;

/** Installed-JAR protocol; all free-form text crosses the locale boundary as UTF-8. */
public final class MatchedElfAllocationsProbe {
    private MatchedElfAllocationsProbe() {
    }

    private static String encoded(String value) {
        return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    public static void main(String[] arguments) throws Exception {
        boolean reject = arguments.length > 0 && arguments[0].equals("--expect-rejection");
        int start = reject ? 1 : 0;
        if (arguments.length <= start || (arguments.length - start) % 2 != 0) {
            throw new IllegalArgumentException("supply original/candidate pairs");
        }
        System.out.println("allocation-class-source=" + MatchedElfAllocations.class.getProtectionDomain()
            .getCodeSource().getLocation().toURI());
        System.out.println("elf-image-class-source=" + ElfImage.class.getProtectionDomain()
            .getCodeSource().getLocation().toURI());
        System.out.println("java-version=" + System.getProperty("java.version"));
        System.out.println("max-heap=" + Runtime.getRuntime().maxMemory());
        for (int index = start; index < arguments.length; index += 2) {
            try {
                var result = MatchedElfAllocations.compare(Path.of(arguments[index]), Path.of(arguments[index + 1]));
                if (reject) {
                    throw new AssertionError("malformed ELF returned an allocation observation");
                }
                String issue = "NONE";
                if (result.issue().isPresent()) {
                    var item = result.issue().get();
                    issue = String.join("\t", item.origin().name(), Integer.toString(item.originalIndex()),
                        Integer.toString(item.candidateIndex()), encoded(item.field()), encoded(item.reason()),
                        encoded(item.expected()), encoded(item.observed()));
                }
                System.out.println(String.join("\t", "allocation", Integer.toString((index - start) / 2),
                    result.status().name(), encoded(result.diagnostic()), issue));
            }
            catch (IOException failure) {
                if (!reject) {
                    throw failure;
                }
                if (failure.getMessage() == null || failure.getMessage().isBlank()) {
                    throw new AssertionError("rejection has no diagnostic", failure);
                }
                System.out.println("rejected\t" + failure.getClass().getName() + "\t" + encoded(failure.getMessage()));
            }
        }
    }
}
