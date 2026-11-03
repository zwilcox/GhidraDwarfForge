package ghidradwarfforge.output;

import ghidradwarfforge.elf.OwnedDebuglinkCandidate;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Test-only bridge from a retained real export to the filesystem controller.
 * The driver MUST freshly validate its selected pair and retain evidence before
 * invoking this probe. This does not provide production validator supervision,
 * a production host metadata contract, or an attachment CLI.
 */
public final class AttachmentElfTransactionProbe {
    private static final class Host extends AttachmentReceiptStoreSmoke.Host implements AttachmentTargetStore.Host {
        public void replaceAtomic(Path stage, Path target) throws IOException {
            Files.move(stage, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 7 || !(args[6].equals("commit") || args[6].equals("rollback"))) {
            throw new IllegalArgumentException("supply report original sidecar source validation-evidence fresh-directory commit|rollback");
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
            Path destination = parent.resolve(entry.getValue().path().getFileName());
            Files.copy(entry.getValue().path(), destination, StandardCopyOption.COPY_ATTRIBUTES);
            paths.put(entry.getKey(), destination);
        }
        var binding = AttachmentExportBinding.observe(paths.get("exportReport"), paths.get("exportOriginal"),
            paths.get("sidecar"), paths.get("source"), host, () -> false);
        var original = binding.files().get("exportOriginal");
        var all = new ArrayList<AttachmentPaths.Selection>();
        for (var entry : paths.entrySet()) {
            all.add(new AttachmentPaths.Selection(entry.getKey(), entry.getValue(), AttachmentPaths.Kind.INPUT));
        }
        all.add(new AttachmentPaths.Selection("originalBackup", parent.resolve("original.backup"), AttachmentPaths.Kind.NEW_FILE));
        all.add(new AttachmentPaths.Selection("receipt", parent.resolve("transaction.json"), AttachmentPaths.Kind.NEW_FILE));
        all.add(new AttachmentPaths.Selection("recoveryReceipt", parent.resolve("recovery.json"), AttachmentPaths.Kind.NEW_FILE));
        all.add(new AttachmentPaths.Selection("restoreImage", parent.resolve("restore.elf"), AttachmentPaths.Kind.NEW_FILE));
        var preflight = AttachmentPaths.preflight(all);
        preflight.recheck();
        var backup = AttachmentFileStore.backup(original, preflight.paths().get("originalBackup"), host, () -> false);
        var candidate = OwnedDebuglinkCandidate.create(backup.path(), paths.get("sidecar"),
            paths.get("sidecar").getFileName().toString().getBytes(StandardCharsets.UTF_8), parent);
        try (var output = FileChannel.open(candidate.candidate(), StandardOpenOption.WRITE)) {
            host.preserveMetadata(original.path(), original.fingerprint(), candidate.candidate());
            output.force(true);
        }
        host.syncDirectory(candidate.directory());
        var after = AttachmentFileStore.observe(candidate.candidate(), host, () -> false);
        Map<String, AttachmentReceipt.Artifact> files = new HashMap<>();
        for (String role : new String[] {"exportReport", "sidecar", "source"}) {
            files.put(role, binding.files().get(role).artifact());
        }
        files.put("validationEvidence", AttachmentFileStore.observe(paths.get("validationEvidence"), host, () -> false).artifact());
        files.put("targetBefore", original.artifact());
        files.put("targetAfter", new AttachmentReceipt.Artifact(original.path().toString(), after.digest().sha256(),
            after.digest().byteCount(), after.fingerprint().identity(), after.fingerprint().metadataSha256()));
        files.put("originalBackup", backup.artifact());
        paths.remove("exportOriginal");
        paths.put("targetBefore", original.path());
        paths.put("targetAfter", after.path());
        paths.put("originalBackup", backup.path());
        var receipt = new AttachmentReceipt(UUID.randomUUID().toString(), AttachmentReceipt.Mode.INITIAL,
            AttachmentReceipt.Phase.PREPARED, preflight.paths().get("receipt").toString(), "owned-append-v1",
            host.contract(), host.durability(), binding.files().get("sidecar").digest().gnuDebuglinkCrc32(), files, null);
        var request = new AttachmentTransaction.Request(receipt, paths, preflight.paths().get("receipt"),
            preflight.paths().get("recoveryReceipt"), preflight.paths().get("restoreImage"));
        binding.recheck(host, () -> false);
        var result = AttachmentTransaction.commit(request, host, () -> false,
            boundary -> {
                if (args[6].equals("rollback") && boundary == AttachmentTransaction.Boundary.TARGET_REPLACED) {
                    throw new IOException("test fault after real ELF replacement");
                }
            }, AttachmentTransaction.RECEIPTS);
        var expected = args[6].equals("commit") ? AttachmentReceipt.Phase.COMMITTED : AttachmentReceipt.Phase.ROLLED_BACK;
        if (result.outcome() != expected) throw new AssertionError(result);
        var installed = AttachmentFileStore.observe(original.path(), host, () -> false);
        if (!installed.digest().equals(args[6].equals("commit") ? after.digest() : original.digest())) {
            throw new AssertionError("unexpected installed ELF bytes");
        }
        AttachmentFileStore.unchanged(backup, host, () -> false);
        for (var input : protectedInputs.values()) AttachmentFileStore.unchanged(input, host, () -> false);
        System.out.println("attachment-elf-controller=PASS outcome=" + result.outcome() +
            " target=" + original.path() + " report-status=" + binding.claims().status() +
            " report-validation=" + binding.claims().validationStatus() + " host=test-only");
    }
}
