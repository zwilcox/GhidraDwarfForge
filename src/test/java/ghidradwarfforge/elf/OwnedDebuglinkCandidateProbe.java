package ghidradwarfforge.elf;

import ghidradwarfforge.output.FileDigests;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Optional;

/** Installed-JAR creation adapter; only a returned owned candidate is exposed. */
public final class OwnedDebuglinkCandidateProbe {
    private OwnedDebuglinkCandidateProbe() {
    }

    public static void main(String[] arguments) throws Exception {
        boolean rejected = arguments.length > 0 && arguments[0].equals("--expect-rejection");
        boolean badArgument = arguments.length > 0 && arguments[0].equals("--expect-argument-rejection");
        int start = rejected || badArgument ? 1 : 0;
        if (arguments.length - start != 4) {
            throw new IllegalArgumentException("supply basename-base64 original sidecar workspace-parent");
        }
        origin("owned-candidate", OwnedDebuglinkCandidate.class);
        origin("candidate-content", DebuglinkCandidateContent.class);
        origin("program-bytes", ExecutableProgramBytes.class);
        origin("elf", ElfImage.class);
        origin("digests", FileDigests.class);
        System.out.println("java-version=" + System.getProperty("java.version"));
        System.out.println("max-heap=" + Runtime.getRuntime().maxMemory());
        for (int at = start; at < arguments.length; at += 4) {
            int index = (at - start) / 4;
            try {
                var created = OwnedDebuglinkCandidate.create(Path.of(arguments[at + 1]),
                    Path.of(arguments[at + 2]), Base64.getDecoder().decode(arguments[at]),
                    Path.of(arguments[at + 3]));
                var result = created.content();
                if (rejected || badArgument) {
                    throw new AssertionError("expected parse/I/O rejection returned content observations");
                }
                if (!created.candidate().getFileName().toString().equals("candidate.elf")) {
                    throw new AssertionError("unexpected owned candidate leaf");
                }
                System.out.println("directory-base64=" + base64(created.directory().toString()));
                System.out.println("candidate-base64=" + base64(created.candidate().toString()));
                var program = result.programBytes();
                String programIssue = program.issue().map(issue -> issue.region().name() + "\t" +
                    (issue.offset().isPresent() ? Long.toString(issue.offset().getAsLong()) : "-") +
                    "\t" + base64(issue.expected()) + "\t" + base64(issue.observed())).orElse("NONE");
                System.out.println("program-bytes\t" + index + "\t" + program.status().name() +
                    "\t" + base64(program.diagnostic()) + "\t" + programIssue);
                var allocated = result.allocatedSections();
                observation("allocated-sections", index, allocated.status().name(),
                    allocated.diagnostic(), allocated.issue());
                var link = result.newDebuglink();
                observation("new-debuglink", index, link.status().name(), link.diagnostic(), link.issue());
                var digest = result.sidecarDigest();
                System.out.println("sidecar-digest\t" + index + "\t" + digest.sha256() + "\t" +
                    digest.gnuDebuglinkCrc32() + "\t" + digest.byteCount());
            }
            catch (IOException | IllegalArgumentException failure) {
                if (failure instanceof IOException ? !rejected : !badArgument) {
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

    private static void observation(String label, int index, String status, String diagnostic,
            Optional<DebuglinkCandidateContent.Issue> issue) {
        String fields = issue.map(value -> value.originalIndex() + "\t" + value.candidateIndex() +
            "\t" + base64(value.field()) + "\t" + base64(value.expected()) + "\t" +
            base64(value.observed())).orElse("NONE");
        System.out.println(label + "\t" + index + "\t" + status + "\t" + base64(diagnostic) + "\t" + fields);
    }

    private static void origin(String label, Class<?> type) throws Exception {
        System.out.println(label + "-class-source=" + type.getProtectionDomain()
            .getCodeSource().getLocation().toURI());
    }

    private static String base64(String value) {
        return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }
}
