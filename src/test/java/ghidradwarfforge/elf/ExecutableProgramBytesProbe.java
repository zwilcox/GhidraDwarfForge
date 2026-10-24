package ghidradwarfforge.elf;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;

/** Installed-JAR adapter; compares explicitly selected files without changing them. */
public final class ExecutableProgramBytesProbe {
    private ExecutableProgramBytesProbe() {
    }

    public static void main(String[] arguments) throws Exception {
        boolean rejected = arguments.length > 0 && arguments[0].equals("--expect-rejection");
        int start = rejected ? 1 : 0;
        if (arguments.length == start || (arguments.length - start) % 2 != 0) {
            throw new IllegalArgumentException("supply pairs of original and candidate paths");
        }
        origin("program-bytes", ExecutableProgramBytes.class);
        origin("elf", ElfImage.class);
        System.out.println("java-version=" + System.getProperty("java.version"));
        System.out.println("max-heap=" + Runtime.getRuntime().maxMemory());
        for (int index = start; index < arguments.length; index += 2) {
            try {
                var result = ExecutableProgramBytes.compare(Path.of(arguments[index]),
                    Path.of(arguments[index + 1]));
                if (rejected) {
                    throw new AssertionError("expected parse/I/O rejection returned an observation");
                }
                String issue = result.issue().map(value -> value.region().name() + "\t" +
                    (value.offset().isPresent() ? Long.toString(value.offset().getAsLong()) : "-") +
                    "\t" + base64(value.expected()) + "\t" + base64(value.observed())).orElse("NONE");
                System.out.println("program-bytes\t" + ((index - start) / 2) + "\t" +
                    result.status().name() + "\t" + base64(result.diagnostic()) + "\t" + issue);
            }
            catch (IOException failure) {
                if (!rejected) {
                    throw failure;
                }
                if (failure.getMessage() == null || failure.getMessage().isBlank()) {
                    throw new AssertionError("rejection has no diagnostic", failure);
                }
                System.out.println("rejected=" + failure.getClass().getName() +
                    " diagnostic=" + base64(failure.getMessage()));
            }
        }
    }

    private static void origin(String label, Class<?> type) throws Exception {
        System.out.println(label + "-class-source=" + type.getProtectionDomain()
            .getCodeSource().getLocation().toURI());
    }

    private static String base64(String value) {
        return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }
}
