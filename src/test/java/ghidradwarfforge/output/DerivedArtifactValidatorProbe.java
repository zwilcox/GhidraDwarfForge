package ghidradwarfforge.output;

import java.nio.file.Path;

/** Real validators and byte proof, with the explicitly test-only metadata host. */
public final class DerivedArtifactValidatorProbe {
    public static void main(String[] args) throws Exception {
        if (args.length != 12) throw new IllegalArgumentException(
            "report original exported-sidecar exported-source derived-sidecar retained-source helper readelf llvm strict configuration evidence");
        var host = new AttachmentElfTransactionProbe.Host();
        var export = AttachmentExportBinding.observe(Path.of(args[0]), Path.of(args[1]), Path.of(args[2]),
            Path.of(args[3]), host, () -> false);
        var derived = ArtifactValidationBinding.relocated(export, Path.of(args[4]), Path.of(args[5]), host, () -> false);
        var validator = new AttachmentValidator(Path.of(args[6]), Path.of(args[7]), Path.of(args[8]),
            Path.of(args[9]), Path.of(args[10]));
        validator.validate(derived, Path.of(args[11]), host, () -> false);
        derived.recheck(host, () -> false);
        System.out.println("derived-artifact-validator=PASS");
    }
}
