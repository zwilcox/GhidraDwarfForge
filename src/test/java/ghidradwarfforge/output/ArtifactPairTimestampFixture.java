package ghidradwarfforge.output;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.FileTime;
import java.util.Arrays;

/** Deterministic delayed-source callback for the real GDB freshness regression. */
public final class ArtifactPairTimestampFixture {
    private ArtifactPairTimestampFixture() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 4) {
            throw new IllegalArgumentException("expected template-dbg template-source output-dbg output-source");
        }
        Path template = Path.of(args[0]);
        Path templateSource = Path.of(args[1]);
        Path output = Path.of(args[2]);
        Path outputSource = Path.of(args[3]);
        ArtifactPairPublisher.stageAndPublish(output, outputSource,
            stage -> {
                Files.copy(template, stage, StandardCopyOption.REPLACE_EXISTING);
                Files.setLastModifiedTime(stage, FileTime.fromMillis(1_700_000_001_000L));
            }, stage -> {
                Files.copy(templateSource, stage, StandardCopyOption.REPLACE_EXISTING);
                Files.setLastModifiedTime(stage, FileTime.fromMillis(1_700_000_002_000L));
            }, () -> { });
        if (Files.getLastModifiedTime(output).compareTo(Files.getLastModifiedTime(outputSource)) < 0) {
            throw new AssertionError("published source is newer than its debug objfile");
        }
        if (!Arrays.equals(Files.readAllBytes(template), Files.readAllBytes(output)) ||
                !Arrays.equals(Files.readAllBytes(templateSource), Files.readAllBytes(outputSource))) {
            throw new AssertionError("publication changed artifact bytes");
        }
        System.out.println("artifact-pair-timestamp-fixture=PASS");
    }
}
