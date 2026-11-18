package ghidradwarfforge.output;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public final class AttachmentProtocolSmoke {
    private static final String BEFORE = "a".repeat(64);
    private static final String AFTER = "b".repeat(64);
    private static final String METADATA = "c".repeat(64);
    private static int checks;

    public static void main(String[] args) throws Exception {
        receipts();
        Path root = Files.createTempDirectory("forge-attachment-protocol-");
        try {
            paths(root);
            AttachmentPathBoundarySmoke.exercise(Files.createDirectory(root.resolve("boundaries")));
            receiptFiles(root);
        }
        finally {
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                    Files.delete(path);
                }
            }
        }
        System.out.println("attachment-protocol-smoke=PASS checks=" + checks);
    }

    static AttachmentReceipt fixture(AttachmentReceipt.Mode mode) {
        Map<String, AttachmentReceipt.Artifact> files = new HashMap<>();
        for (String role : List.of("targetBefore", "targetAfter", "originalBackup", "sidecar",
                "source", "exportReport", "validationEvidence")) {
            files.put(role, artifact(role.equals("targetAfter") ? "targetBefore" : role,
                role.equals("targetAfter") ? AFTER : BEFORE, role));
        }
        if (mode == AttachmentReceipt.Mode.REFRESH) {
            for (String role : List.of("previousReceipt", "previousSidecar", "previousSource", "priorTargetBackup")) {
                files.put(role, artifact(role, BEFORE, role));
            }
        }
        return new AttachmentReceipt("12345678-1234-4234-8234-123456789abc", mode,
            AttachmentReceipt.Phase.PREPARED, "/owned/receipt.json", "forge-owned-append-v1",
            "test-host-v1", "test-only-no-durability", 0xffff_ffffL, files, null);
    }

    private static AttachmentReceipt.Artifact artifact(String name, String hash, String identity) {
        return new AttachmentReceipt.Artifact("/owned/" + name, hash, Long.MAX_VALUE, identity, METADATA);
    }

    private static AttachmentReceipt read(String value) throws IOException {
        return AttachmentReceipt.read(new ByteArrayInputStream(value.getBytes(StandardCharsets.UTF_8)), () -> false);
    }

    private static void receipts() throws Exception {
        for (var mode : AttachmentReceipt.Mode.values()) {
            AttachmentReceipt prepared = fixture(mode);
            receiptBoundaries(prepared);
            equal(prepared, read(prepared.toJson()));
            equal(prepared.toJson(), read(prepared.toJson()).toJson());
            equal(prepared, read(prepared.toJson().replace("\"schemaVersion\":2", "\"schemaVersion\":1")
                .replace(",\"recovery\":null", "")));
            var recovery = prepared.forRecovery("/owned/recovery.json", artifact("receipt.json", BEFORE, "receipt-id"),
                prepared.files().get("targetBefore"));
            equal(recovery, read(recovery.toJson()));
            equal(recovery.advance(AttachmentReceipt.Phase.ROLLED_BACK, "verified prior image"),
                read(recovery.advance(AttachmentReceipt.Phase.ROLLED_BACK, "verified prior image").toJson()));
            rejectState(() -> recovery.advance(AttachmentReceipt.Phase.COMMITTED, null));
            var unknown = prepared.forRecovery("/owned/recovery.json", artifact("receipt.json", BEFORE, "receipt-id"), null);
            rejectArgument(() -> unknown.advance(AttachmentReceipt.Phase.ROLLED_BACK, "no observation"));
            equal(unknown.advance(AttachmentReceipt.Phase.RECOVERY_REQUIRED, "target unreadable"),
                read(unknown.advance(AttachmentReceipt.Phase.RECOVERY_REQUIRED, "target unreadable").toJson()));
            rejectArgument(() -> prepared.forRecovery("/owned/recovery.json", artifact("receipt.json", BEFORE, "receipt-id"),
                prepared.files().get("targetAfter")).advance(AttachmentReceipt.Phase.ROLLED_BACK, "wrong image"));
            for (String malformed : List.of(
                    recovery.toJson().replace("\"schemaVersion\":2", "\"schemaVersion\":1"),
                    recovery.toJson().replace("\"observedTarget\"", "\"unknownObservation\""),
                    recovery.toJson().replace("\"observedTarget\":", "\"priorReceipt\":"),
                    recovery.toJson().replace("/owned/receipt.json", "/owned/originalBackup"))) {
                rejectIO(() -> read(malformed));
            }
            for (var phase : List.of(AttachmentReceipt.Phase.COMMITTED,
                    AttachmentReceipt.Phase.ROLLED_BACK, AttachmentReceipt.Phase.RECOVERY_REQUIRED)) {
                var next = prepared.advance(phase, phase == AttachmentReceipt.Phase.COMMITTED ? null : "owned failure");
                equal(next, read(next.toJson()));
                if (phase != AttachmentReceipt.Phase.RECOVERY_REQUIRED) {
                    rejectState(() -> next.advance(AttachmentReceipt.Phase.ROLLED_BACK, "forbidden"));
                }
                else {
                    equal(AttachmentReceipt.Phase.ROLLED_BACK,
                        next.advance(AttachmentReceipt.Phase.ROLLED_BACK, "recovered").phase());
                    rejectState(() -> next.advance(AttachmentReceipt.Phase.COMMITTED, null));
                }
            }
            rejectState(() -> prepared.advance(AttachmentReceipt.Phase.PREPARED, null));
            String json = prepared.toJson();
            for (String malformed : List.of(
                    json.replace("\"schemaVersion\":2", "\"schemaVersion\":3"),
                    json.replace("\"schemaVersion\":2", "\"schemaVersion\":2,\"schemaVersion\":2"),
                    json.replace("\"bytes\":\"9223372036854775807\"", "\"bytes\":9223372036854775807"),
                    json.replace("9223372036854775807", "9223372036854775808"),
                    json.replace("9223372036854775807", "01"),
                    json.replace("\"diagnostic\":null", "\"diagnostic\":\"not allowed\""),
                    json.replace("\"diagnostic\":null", "\"other\":null"),
                    json.replace("\"debuglinkCrc32\":4294967295", "\"debuglinkCrc32\":4294967296"),
                    json.replace("\"debuglinkCrc32\":4294967295", "\"debuglinkCrc32\":1.5"),
                    json.replace("test-host-v1", "x".repeat(16385)),
                    json.replace("/owned/source", "/owned/sidecar"),
                    json.replace("\"targetAfter\"", "\"targetBefore\""),
                    json.replace(AFTER, BEFORE),
                    json.replace("/owned/source", "/owned/\\u0000source"),
                    json.replace("/owned/source", "/owned/\\ud800source"),
                    json + "{}", "\ufeff" + json, json.substring(0, json.length() - 2))) {
                rejectIO(() -> read(malformed));
            }
            var wrong = new HashMap<>(prepared.files());
            wrong.put(mode == AttachmentReceipt.Mode.INITIAL ? "originalBackup" : "priorTargetBackup",
                artifact("wrong-backup", AFTER, "separate-inode"));
            rejectArgument(() -> new AttachmentReceipt(prepared.operationId(), mode, prepared.phase(),
                prepared.receiptPath(), prepared.backend(), prepared.hostContract(), prepared.durability(),
                prepared.debuglinkCrc32(), wrong, null));
        }
        AtomicBoolean closed = new AtomicBoolean();
        var input = new ByteArrayInputStream(fixture(AttachmentReceipt.Mode.INITIAL).toJson()
                .getBytes(StandardCharsets.UTF_8)) {
            @Override public void close() throws IOException {
                closed.set(true);
                super.close();
            }
        };
        try {
            AttachmentReceipt.read(input, () -> true);
            throw new AssertionError("receipt cancellation ignored");
        }
        catch (CancellationException expected) {
            equal(true, closed.get());
        }
        rejectIO(() -> AttachmentReceipt.read(new ByteArrayInputStream(new byte[] {(byte) 0xff}), () -> false));
    }

    private static void receiptBoundaries(AttachmentReceipt prepared) throws Exception {
        JsonObject valid = JsonParser.parseString(prepared.toJson()).getAsJsonObject();
        for (String id : List.of("not-a-uuid", "1-1-1-1-1", prepared.operationId().toUpperCase(java.util.Locale.ROOT))) {
            malformed(valid, json -> json.addProperty("operationId", id), "invalid attachment receipt");
        }
        malformed(valid, json -> json.addProperty("debuglinkCrc32", -1), "invalid character outside a report string");
        rejectArgument(() -> new AttachmentReceipt(prepared.operationId(), prepared.mode(), prepared.phase(), prepared.receiptPath(),
            prepared.backend(), prepared.hostContract(), prepared.durability(), -1, prepared.files(), null));
        for (String field : List.of("backend", "hostContract", "durability")) {
            for (String identifier : List.of("", "Bad", "space value", "x".repeat(65))) {
                malformed(valid, json -> json.addProperty(field, identifier), "invalid attachment contract identifier");
            }
        }
        for (String field : List.of("path", "identity")) {
            for (String invalid : List.of("", "x".repeat(field.equals("path") ? 16385 : 4097),
                    "delete\u007f", "low\udc00", "high\ud800", "pair\ud800x")) {
                String diagnostic = invalid.length() > 16384 ? "string exceeds safety limit" :
                    invalid.indexOf('\ud800') >= 0 ? "unpaired high surrogate" :
                    invalid.indexOf('\udc00') >= 0 ? "unpaired low surrogate" : "attachment";
                malformed(valid, json -> artifact(json, "sidecar").addProperty(field, invalid), diagnostic);
                rejectArgument(() -> new AttachmentReceipt.Artifact(field.equals("path") ? invalid : "path",
                    BEFORE, 0, field.equals("identity") ? invalid : "id", METADATA));
            }
        }
        for (String field : List.of("sha256", "metadataSha256")) {
            for (String invalid : List.of("", "A".repeat(64), "a".repeat(63), "g".repeat(64))) {
                malformed(valid, json -> artifact(json, "sidecar").addProperty(field, invalid), "invalid attachment SHA-256");
            }
        }
        malformed(valid, json -> artifact(json, "targetAfter").addProperty("path", "/different"), "distinct images");
        malformed(valid, json -> artifact(json, "targetAfter").addProperty("identity", "targetBefore"), "distinct images");
        malformed(valid, json -> artifact(json, "targetAfter").addProperty("metadataSha256", AFTER), "distinct images");
        String backup = prepared.mode() == AttachmentReceipt.Mode.INITIAL ? "originalBackup" : "priorTargetBackup";
        for (String field : List.of("bytes", "metadataSha256", "identity")) {
            malformed(valid, json -> artifact(json, backup).addProperty(field,
                field.equals("bytes") ? "0" : field.equals("identity") ? "targetBefore" : AFTER), "independently preserve");
        }
        malformed(valid, json -> json.getAsJsonObject("files").remove("source"), "artifact roles");
        malformed(valid, json -> json.getAsJsonObject("files").add("invented", artifact(json, "source").deepCopy()), "unknown attachment artifact role");
        malformed(valid, json -> artifact(json, "source").addProperty("unknown", "value"), "unknown attachment artifact field");
        malformed(valid, json -> artifact(json, "source").remove("bytes"), "invalid attachment artifact shape");
        malformed(valid, json -> json.remove("diagnostic"), "incomplete or unsupported attachment receipt schema");
        for (String value : List.of("-1", "1.0", "+1", " 1", "1e2")) {
            malformed(valid, json -> artifact(json, "source").addProperty("bytes", value), "invalid attachment artifact shape");
        }
        for (AttachmentReceipt.Phase phase : List.of(AttachmentReceipt.Phase.ROLLED_BACK, AttachmentReceipt.Phase.RECOVERY_REQUIRED)) {
            malformed(valid, json -> json.addProperty("phase", phase.name()), "outcome and diagnostic disagree");
        }
        JsonObject recovery = JsonParser.parseString(prepared.forRecovery("/owned/recovery.json",
            artifact("receipt.json", BEFORE, "prior-receipt"), prepared.files().get("targetBefore")).toJson()).getAsJsonObject();
        malformed(recovery, json -> json.addProperty("phase", "COMMITTED"), "invalid recovery receipt phase");
        malformed(recovery, json -> json.getAsJsonObject("recovery").getAsJsonObject("observedTarget")
            .addProperty("path", "/different"), "selected target path");
        for (String missing : List.of("observedTarget", "priorReceipt")) {
            malformed(recovery, json -> json.getAsJsonObject("recovery").remove(missing), "incomplete recovery receipt evidence");
        }
        for (String field : List.of("bytes", "metadataSha256")) {
            malformed(recovery, json -> {
                json.addProperty("phase", "ROLLED_BACK");
                json.addProperty("diagnostic", "restored");
                json.getAsJsonObject("recovery").getAsJsonObject("observedTarget")
                    .addProperty(field, field.equals("bytes") ? "0" : AFTER);
            }, "complete prior image and metadata");
        }
        var before = prepared.files().get("targetBefore");
        rejectArgument(() -> new AttachmentReceipt.Artifact(before.path(), before.sha256(), -1, before.identity(), before.metadataSha256()));
        rejectArgument(() -> new AttachmentReceipt.Artifact(null, BEFORE, 0, "id", METADATA));
        rejectArgument(() -> new AttachmentReceipt.Artifact("path", null, 0, "id", METADATA));
        rejectArgument(() -> new AttachmentReceipt.Artifact("path", BEFORE, 0, "id", null));
        rejectArgument(() -> new AttachmentReceipt.Artifact("path", BEFORE, 0, null, METADATA));
        rejectArgument(() -> new AttachmentReceipt(null, prepared.mode(), prepared.phase(), prepared.receiptPath(),
            prepared.backend(), prepared.hostContract(), prepared.durability(), 0, prepared.files(), null));
        rejectArgument(() -> new AttachmentReceipt(prepared.operationId(), prepared.mode(), prepared.phase(), prepared.receiptPath(),
            null, prepared.hostContract(), prepared.durability(), 0, prepared.files(), null));
        // Valid supplementary Unicode and exact upper bounds must survive; the
        // parser must not "fix" malformed strings by refusing all non-ASCII paths.
        JsonObject unicode = valid.deepCopy();
        artifact(unicode, "source").addProperty("path", "/source/\ud83d\udd0d.c");
        artifact(unicode, "source").addProperty("identity", "id-\ud83d\udd0d");
        equal("/source/\ud83d\udd0d.c", read(unicode.toString()).files().get("source").path());
        equal(new AttachmentReceipt.Artifact("p".repeat(16384), BEFORE, 0, "i".repeat(4096), METADATA).bytes(), 0L);
        cancellationAndStreamClosure(prepared.toJson());
    }

    private static JsonObject artifact(JsonObject receipt, String role) {
        return receipt.getAsJsonObject("files").getAsJsonObject(role);
    }

    private static void malformed(JsonObject valid, Consumer<JsonObject> change, String diagnostic) throws Exception {
        String unchanged = valid.toString();
        JsonObject invalid = valid.deepCopy();
        change.accept(invalid);
        AtomicBoolean closed = new AtomicBoolean();
        try {
            // JSON escapes retain deliberately invalid UTF-16 code units;
            // UTF-8 encoding an unpaired surrogate would replace it with '?'.
            StringBuilder encoded = new StringBuilder();
            for (char unit : invalid.toString().toCharArray()) {
                if (Character.isSurrogate(unit)) encoded.append(String.format("\\u%04x", (int) unit));
                else encoded.append(unit);
            }
            AttachmentReceipt.read(closing(encoded.toString(), closed), () -> false);
            throw new AssertionError("accepted malformed receipt: " + diagnostic);
        }
        catch (IOException expected) {
            String message = expected.toString();
            for (Throwable cause = expected.getCause(); cause != null; cause = cause.getCause()) message += " " + cause;
            if (!message.contains(diagnostic)) throw new AssertionError("wrong rejection: " + message, expected);
            checks++;
        }
        equal(true, closed.get());
        equal(unchanged, valid.toString());
    }

    private static ByteArrayInputStream closing(String json, AtomicBoolean closed) {
        return new ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8)) {
            @Override public void close() throws IOException {
                closed.set(true);
                super.close();
            }
        };
    }

    private static void cancellationAndStreamClosure(String json) throws Exception {
        AtomicInteger visits = new AtomicInteger();
        AtomicBoolean closed = new AtomicBoolean();
        AttachmentReceipt.read(closing(json, closed), () -> { visits.incrementAndGet(); return false; });
        equal(true, closed.get());
        for (int stop = 1; stop <= visits.get(); stop++) {
            int selected = stop;
            AtomicInteger current = new AtomicInteger();
            closed.set(false);
            try {
                AttachmentReceipt.read(closing(json, closed), () -> current.incrementAndGet() == selected);
                throw new AssertionError("missed receipt cancellation " + stop);
            }
            catch (CancellationException expected) { checks++; }
            equal(true, closed.get());
        }
    }

    private static void receiptFiles(Path root) throws Exception {
        var prepared = fixture(AttachmentReceipt.Mode.INITIAL);
        Path path = Files.writeString(root.resolve("claims.json"), prepared.toJson());
        byte[] before = Files.readAllBytes(path);
        equal(prepared, AttachmentReceipt.read(path, () -> false));
        rejectIO(() -> AttachmentReceipt.read(root, () -> false));
        rejectIO(() -> AttachmentReceipt.read(root.resolve("absent.json"), () -> false));
        try {
            AttachmentReceipt.read(path, () -> true);
            throw new AssertionError("path cancellation ignored");
        }
        catch (CancellationException expected) { checks++; }
        equal(true, java.util.Arrays.equals(before, Files.readAllBytes(path)));
    }

    private static void paths(Path root) throws Exception {
        List<AttachmentPaths.Selection> selected = new ArrayList<>();
        for (String role : List.of("target", "sidecar", "source", "report", "validation", "previousReceipt")) {
            Path file = Files.writeString(root.resolve(role), "original:" + role);
            selected.add(new AttachmentPaths.Selection(role, file,
                role.equals("target") ? AttachmentPaths.Kind.TARGET : AttachmentPaths.Kind.INPUT));
        }
        for (String role : List.of("backup", "receipt", "log")) {
            selected.add(new AttachmentPaths.Selection(role, root.resolve(role), AttachmentPaths.Kind.NEW_FILE));
        }
        var plan = AttachmentPaths.preflight(selected);
        plan.recheck();
        equal(9, plan.paths().size());
        for (int first = 0; first < selected.size(); first++) {
            for (int second = first + 1; second < selected.size(); second++) {
                var alias = new ArrayList<>(selected);
                var original = alias.get(first);
                var replaced = alias.get(second);
                alias.set(second, new AttachmentPaths.Selection(replaced.role(), original.path(), replaced.kind()));
                rejectIO(() -> AttachmentPaths.preflight(alias));
            }
        }
        Path hardlink = Files.createLink(root.resolve("hardlink"), root.resolve("target"));
        Path symlink = Files.createSymbolicLink(root.resolve("symlink"), root.resolve("target"));
        Path dangling = Files.createSymbolicLink(root.resolve("dangling"), root.resolve("absent"));
        for (Path alias : List.of(hardlink, symlink)) {
            var changed = new ArrayList<>(selected);
            changed.set(1, new AttachmentPaths.Selection("sidecar", alias, AttachmentPaths.Kind.INPUT));
            rejectIO(() -> AttachmentPaths.preflight(changed));
        }
        for (Path invalid : List.of(symlink, dangling, root)) {
            var changed = new ArrayList<>(selected);
            changed.set(0, new AttachmentPaths.Selection("target", invalid, AttachmentPaths.Kind.TARGET));
            rejectIO(() -> AttachmentPaths.preflight(changed));
        }
        rejectIO(() -> AttachmentPaths.preflight(List.of(
            new AttachmentPaths.Selection("backup", dangling, AttachmentPaths.Kind.NEW_FILE))));
        Path actual = Files.createDirectories(root.resolve("actual/child"));
        Path traversed = Files.writeString(actual.getParent().resolve("input"), "traversal sentinel");
        Files.createSymbolicLink(root.resolve("parent-link"), actual);
        rejectIO(() -> AttachmentPaths.preflight(List.of(
            new AttachmentPaths.Selection("input", traversed, AttachmentPaths.Kind.INPUT),
            new AttachmentPaths.Selection("alias", root.resolve("parent-link/../input"), AttachmentPaths.Kind.INPUT))));
        for (var selection : selected) {
            if (selection.kind() == AttachmentPaths.Kind.NEW_FILE) {
                equal(false, Files.exists(selection.path(), java.nio.file.LinkOption.NOFOLLOW_LINKS));
            }
            else {
                equal("original:" + selection.role(), Files.readString(selection.path()));
            }
        }
        Files.writeString(root.resolve("sidecar"), "concurrently changed sidecar");
        rejectIO(plan::recheck);
        var newPlan = AttachmentPaths.preflight(selected);
        Files.writeString(root.resolve("log"), "concurrent log sentinel");
        rejectIO(newPlan::recheck);
        equal("concurrent log sentinel", Files.readString(root.resolve("log")));
    }

    @FunctionalInterface private interface Checked { void run() throws Exception; }
    private static void rejectIO(Checked action) throws Exception {
        try { action.run(); throw new AssertionError("invalid input accepted"); }
        catch (IOException expected) { checks++; }
    }
    private static void rejectState(Checked action) throws Exception {
        try { action.run(); throw new AssertionError("invalid transition accepted"); }
        catch (IllegalStateException expected) { checks++; }
    }
    private static void rejectArgument(Checked action) throws Exception {
        try { action.run(); throw new AssertionError("invalid claim accepted"); }
        catch (IllegalArgumentException expected) { checks++; }
    }
    private static void equal(Object expected, Object actual) {
        if (!expected.equals(actual)) throw new AssertionError(expected + " != " + actual);
        checks++;
    }
}
