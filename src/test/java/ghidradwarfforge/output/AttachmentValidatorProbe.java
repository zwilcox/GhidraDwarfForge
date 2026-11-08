package ghidradwarfforge.output;

import java.nio.file.Files;
import java.nio.file.Path;

/** Test entry point to the production validator; it never replaces an executable. */
public final class AttachmentValidatorProbe {
    public static void main(String[] args) throws Exception {
        if (args.length != 10 && args.length != 11) throw new IllegalArgumentException(
            "report original sidecar source helper readelf llvm raw-strict configuration new-evidence [cancel-marker]");
        var host = new AttachmentElfTransactionProbe.Host();
        var binding = AttachmentExportBinding.observe(Path.of(args[0]), Path.of(args[1]), Path.of(args[2]),
            Path.of(args[3]), host, () -> false);
        var validator = new AttachmentValidator(Path.of(args[4]), Path.of(args[5]), Path.of(args[6]),
            Path.of(args[7]), Path.of(args[8]));
        validator.validate(binding, Path.of(args[9]), host, () -> args.length == 11 && Files.exists(Path.of(args[10])));
        System.out.println("attachment-validator=PASS");
    }
}
