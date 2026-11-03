package ghidradwarfforge.output;

import com.google.gson.JsonParser;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

/**
 * Test-only bridge from a retained real export to the filesystem controller.
 * The driver MUST freshly validate its selected pair and retain evidence before
 * invoking this probe. Optional explicit tool arguments select the production
 * live validator in the operation; the shorter form retains the captured test
 * adapter. Neither form supplies a production host or an attachment CLI.
 */
public final class AttachmentElfTransactionProbe {
    static final class Host extends AttachmentReceiptStoreSmoke.Host implements AttachmentOperation.Host {
        public byte[] debuglinkBasename(Path sidecar) {
            return sidecar.getFileName().toString().getBytes(StandardCharsets.UTF_8);
        }
        public void replaceAtomic(Path stage, Path target) throws IOException {
            Files.move(stage, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    public static void main(String[] args) throws Exception {
        if ((args.length != 7 && args.length != 12) || !(args[6].equals("commit") || args[6].equals("rollback"))) {
            throw new IllegalArgumentException("supply report original sidecar source validation-evidence fresh-directory " +
                "commit|rollback [helper readelf llvm raw-strict-checker configuration]");
        }
        var host = new Host();
        Path parent = Path.of(args[5]).toRealPath();
        if (!Files.isDirectory(parent)) throw new IOException("test parent must exist");
        try (var children = Files.list(parent)) {
            if (children.findAny().isPresent()) throw new IOException("test parent must be empty");
        }
        // All original fixture inputs are read-only; the controller modifies
        // only independently copied files in this explicit empty directory.
        var selections = new ArrayList<AttachmentPaths.Selection>();
        String[] roles = {"exportReport", "exportOriginal", "sidecar", "source", "validationEvidence"};
        Map<String, AttachmentFileStore.Snapshot> protectedInputs = new HashMap<>();
        for (int index = 0; index < roles.length; index++) {
            selections.add(new AttachmentPaths.Selection(roles[index], Path.of(args[index]), AttachmentPaths.Kind.INPUT));
        }
        var selected = AttachmentPaths.preflight(selections);
        for (var entry : selected.paths().entrySet()) {
            protectedInputs.put(entry.getKey(), AttachmentFileStore.observe(entry.getValue(), host, () -> false));
        }
        Map<String, Path> paths = new HashMap<>();
        for (var entry : protectedInputs.entrySet()) {
            if (entry.getKey().equals("source") || entry.getKey().equals("validationEvidence")) {
                paths.put(entry.getKey(), entry.getValue().path());
            }
            else {
                Path destination = parent.resolve(entry.getValue().path().getFileName());
                Files.copy(entry.getValue().path(), destination, StandardCopyOption.COPY_ATTRIBUTES);
                paths.put(entry.getKey(), destination);
            }
        }
        var binding = AttachmentExportBinding.observe(paths.get("exportReport"), paths.get("exportOriginal"),
            paths.get("sidecar"), paths.get("source"), host, () -> false);
        var original = binding.files().get("exportOriginal");
        var request = new AttachmentOperation.Request(original.path(), paths.get("sidecar"), paths.get("source"),
            paths.get("exportReport"), parent.resolve("original.backup"), parent.resolve("validation.json"),
            parent.resolve("transaction.json"), parent.resolve("recovery.json"), parent.resolve("restore.elf"), null);
        // Select the live production policy when supplied explicit tools. The
        // shorter historical fixture form rebinds the harness's captured checks.
        AttachmentOperation.Validator validator = args.length == 12
            ? new AttachmentValidator(Path.of(args[7]), Path.of(args[8]), Path.of(args[9]), Path.of(args[10]), Path.of(args[11]))
            : capturedValidator(paths.get("validationEvidence"), host);
        var operation = AttachmentOperation.execute(request, host, validator, () -> false,
            boundary -> {
                if (args[6].equals("rollback") && boundary == AttachmentTransaction.Boundary.TARGET_REPLACED) {
                    throw new IOException("test fault after real ELF replacement");
                }
            });
        var result = operation.transaction();
        var after = operation.recoveryRequest().prepared().files().get("targetAfter");
        var expected = args[6].equals("commit") ? AttachmentReceipt.Phase.COMMITTED : AttachmentReceipt.Phase.ROLLED_BACK;
        if (result.outcome() != expected) throw new AssertionError(result);
        var installed = AttachmentFileStore.observe(original.path(), host, () -> false);
        if (!installed.digest().sha256().equals(args[6].equals("commit") ? after.sha256() : original.digest().sha256())) {
            throw new AssertionError("unexpected installed ELF bytes");
        }
        if (!AttachmentFileStore.observe(request.originalBackup(), host, () -> false).digest().equals(original.digest())) {
            throw new AssertionError("independent original backup changed");
        }
        for (var input : protectedInputs.values()) AttachmentFileStore.unchanged(input, host, () -> false);
        System.out.println("attachment-elf-controller=PASS outcome=" + result.outcome() +
            " target=" + original.path() + " report-status=" + binding.claims().status() +
            " report-validation=" + binding.claims().validationStatus() + " host=test-only");
    }

    static AttachmentOperation.Validator capturedValidator(Path evidencePath, Host host) throws IOException {
        var snapshot = AttachmentFileStore.observe(evidencePath, host, () -> false);
        return (selectedExport, evidence, selectedHost, cancelled) -> {
            AttachmentFileStore.unchanged(snapshot, host, cancelled);
            var captured = JsonParser.parseString(Files.readString(evidencePath)).getAsJsonObject();
            if (!captured.getAsJsonObject("strict").get("status").getAsString().equals("PASS")) {
                throw new IOException("fixture validator evidence did not pass");
            }
            Map<String, String> expectedHashes = new HashMap<>();
            for (var entry : captured.getAsJsonObject("inputs").entrySet()) {
                if (expectedHashes.put(Path.of(entry.getKey()).getFileName().toString(), entry.getValue().getAsString()) != null) {
                    throw new IOException("fixture evidence repeats a basename");
                }
            }
            for (var file : selectedExport.files().values()) {
                if (!file.digest().sha256().equals(expectedHashes.get(file.path().getFileName().toString()))) {
                    throw new IOException("fixture validation does not bind selected bytes");
                }
            }
            AttachmentFileStore.unchanged(snapshot, host, cancelled);
            AttachmentFileStore.backup(snapshot, evidence, selectedHost, cancelled);
        };
    }
}
