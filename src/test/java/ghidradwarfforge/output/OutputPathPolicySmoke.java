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
            // Keep the supplied spelling (which may use a Windows short name)
            // while independently establishing the actual destination directory.
            Path actualDirectory = directory.toRealPath();
            Path input = directory.resolve("program.elf");
            Files.writeString(input, "fixture", StandardCharsets.UTF_8);
            var defaults = OutputPathPolicy.resolve(input, null);
            assertEquals(actualDirectory.resolve("program.elf"), defaults.input());
            assertEquals(actualDirectory.resolve("program.elf.dbg"), defaults.artifact());
            assertEquals(actualDirectory.resolve("program.elf.dbg.c"), defaults.source());
            if (!Files.isSameFile(input, defaults.input())) {
                throw new AssertionError("resolved input selected a different file");
            }
            if (!defaults.defaultOutput()) {
                throw new AssertionError("default output was not identified");
            }

            Path explicit = directory.resolve("chosen.dbg");
            var selected = OutputPathPolicy.resolve(input, explicit);
            assertEquals(actualDirectory.resolve("chosen.dbg"), selected.artifact());
            assertEquals(actualDirectory.resolve("chosen.dbg.c"), selected.source());
            System.out.println("output-policy-requested-parent=" + directory);
            System.out.println("output-policy-actual-parent=" + actualDirectory);
            System.out.println("output-policy-existing-parent=PASS");
            if (selected.defaultOutput()) {
                throw new AssertionError("explicit output was identified as default");
            }

            assertFailure(() -> OutputPathPolicy.resolve(directory.resolve("missing"), null),
                "supply --input");
            Path missingParentInput = directory.resolve("missing-parent/program.elf");
            try {
                OutputPathPolicy.resolve(missingParentInput, null);
                throw new AssertionError("missing input parent was accepted");
            }
            catch (IOException failure) {
                if (!failure.getMessage().contains("supply --input=<path>") ||
                        !failure.getMessage().contains(missingParentInput.getParent().toString()) ||
                        !(failure.getCause() instanceof IOException) ||
                        Files.exists(missingParentInput.getParent())) {
                    throw new AssertionError("missing input parent lost its hint/cause or wrote files", failure);
                }
            }
            assertFailure(() -> OutputPathPolicy.resolve(input, input), "aliases");
            assertFailure(() -> OutputPathPolicy.resolve(input, directory), "cannot replace");
            Path sourceCollision = directory.resolve("collision.dbg.c");
            Files.writeString(sourceCollision, "fixture", StandardCharsets.UTF_8);
            assertFailure(() -> OutputPathPolicy.resolve(sourceCollision,
                directory.resolve("collision.dbg")), "aliases");
            assertFailure(() -> OutputPathPolicy.resolve(input,
                directory.resolve("missing").resolve("chosen.dbg")), "directory");
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
        if (!expected.equals(actual)) {
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
