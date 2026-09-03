package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;

/** Native-independent output naming, collision, and unwritable-path regression. */
public final class OutputPathPolicySmoke {
    private OutputPathPolicySmoke() {
    }

    public static void main(String[] args) throws Exception {
        Path directory = Files.createTempDirectory("forge-output-policy-");
        try {
            Path input = directory.resolve("program.elf");
            Files.writeString(input, "fixture", StandardCharsets.UTF_8);
            var defaults = OutputPathPolicy.resolve(input, null);
            assertEquals(input, defaults.input());
            assertEquals(directory.resolve("program.elf.dbg"), defaults.artifact());
            assertEquals(directory.resolve("program.elf.dbg.c"), defaults.source());
            if (!defaults.defaultOutput()) {
                throw new AssertionError("default output was not identified");
            }

            Path explicit = directory.resolve("chosen.dbg");
            var selected = OutputPathPolicy.resolve(input, explicit);
            assertEquals(explicit, selected.artifact());
            assertEquals(directory.resolve("chosen.dbg.c"), selected.source());
            if (selected.defaultOutput()) {
                throw new AssertionError("explicit output was identified as default");
            }

            assertFailure(() -> OutputPathPolicy.resolve(directory.resolve("missing"), null),
                "supply --input");
            assertFailure(() -> OutputPathPolicy.resolve(input, input), "aliases");
            assertFailure(() -> OutputPathPolicy.resolve(input, directory), "cannot replace");
            Path sourceCollision = directory.resolve("collision.dbg.c");
            Files.writeString(sourceCollision, "fixture", StandardCharsets.UTF_8);
            assertFailure(() -> OutputPathPolicy.resolve(sourceCollision,
                directory.resolve("collision.dbg")), "aliases");
            assertFailure(() -> OutputPathPolicy.resolve(input,
                directory.resolve("missing").resolve("chosen.dbg")), "not writable");
            assertFailure(() -> OutputPathPolicy.resolve(input, explicit, ignored -> false),
                "not writable");
        }
        finally {
            try (var paths = Files.walk(directory)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                    Files.deleteIfExists(path);
                }
            }
        }
        System.out.println("output-path-policy-smoke=PASS");
    }

    private static void assertEquals(Path expected, Path actual) {
        if (!expected.toAbsolutePath().normalize().equals(actual)) {
            throw new AssertionError("expected " + expected + " but found " + actual);
        }
    }

    private static void assertFailure(CheckedOperation operation, String expected)
            throws Exception {
        try {
            operation.run();
            throw new AssertionError("expected path policy failure containing " + expected);
        }
        catch (IOException failure) {
            if (!failure.getMessage().contains(expected)) {
                throw failure;
            }
        }
    }

    @FunctionalInterface
    private interface CheckedOperation {
        void run() throws Exception;
    }
}
