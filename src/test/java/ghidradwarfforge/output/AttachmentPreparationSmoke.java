package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CancellationException;

/** Report/selection preparation controls. Arbitrary bytes deliberately imply no native validation. */
public final class AttachmentPreparationSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("forge-preparation-λ ").toRealPath();
        try {
            Path target = Files.writeString(root.resolve("target"), "original input");
            var tools = new HashMap<String, Path>();
            for (String role : new String[] {"helper", "readelf", "llvm", "strict", "configuration"}) {
                tools.put(role, Files.writeString(root.resolve(role), "unused selected tool " + role));
            }
            var first = AttachmentPreparation.begin(target, root.resolve("first.dbg"), root, tools, null);
            first.recheckBeforeExport();
            String report = completed(root, first, false);
            Path request = first.finish(report, () -> false);
            equal(first.invocation(), AttachmentInvocation.read(request, () -> false));
            first.invocation().preflight(request).recheck();
            equal(ExportReport.Status.SUCCESS, ExportReportClaims.read(first.invocation().operation().exportReport()).status());
            equal("original input", Files.readString(target));
            rejects(() -> first.finish(report, () -> false));
            rejects(() -> AttachmentPreparation.begin(target, first.sidecar(), root, tools, null));
            var collided = new HashMap<>(tools);
            collided.put("helper", target);
            rejects(() -> AttachmentPreparation.begin(target, root.resolve("collision.dbg"), root, collided, null));
            rejects(() -> AttachmentPreparation.begin(target, first.sidecar(), root, tools,
                new AttachmentPreparation.Previous(target, root.resolve("missing-receipt"), first.sidecar(), first.invocation().operation().source())));

            Path backup = Files.writeString(root.resolve("original.backup"), "retained original input");
            Path previousReceipt = Files.writeString(root.resolve("prior.json"), "not parsed until native operation");
            var previous = new AttachmentPreparation.Previous(backup, previousReceipt,
                first.sidecar(), first.invocation().operation().source());
            var refresh = AttachmentPreparation.begin(target, root.resolve("refresh.dbg"), root, tools, previous);
            equal(backup, refresh.exportInput());
            refresh.finish(completed(root, refresh, true), () -> false);
            equal(ExportReport.Status.PARTIAL, ExportReportClaims.read(refresh.invocation().operation().exportReport()).status());
            equal("original input", Files.readString(target));
            equal("retained original input", Files.readString(backup));

            for (String mode : new String[] {"cancel", "fatal", "changed", "mismatch"}) {
                var plan = AttachmentPreparation.begin(target, root.resolve(mode + ".dbg"), root, tools, null);
                String captured = completed(root, plan, false);
                if (mode.equals("changed")) Files.writeString(plan.invocation().operation().source(), "changed after report");
                if (mode.equals("mismatch")) captured = captured.replace(FileDigests.read(target).sha256(), "0".repeat(64));
                if (mode.equals("fatal")) captured = ExportReport.terminal(ExportReport.Status.FATAL, new IOException("fixture failure")).toJson();
                final String selectedReport = captured;
                rejects(() -> plan.finish(selectedReport, () -> mode.equals("cancel")));
                equal(false, Files.exists(plan.request()));
                equal(false, Files.exists(plan.invocation().operation().exportReport()));
                equal("original input", Files.readString(target));
            }
            System.out.println("attachment-preparation=PASS checks=" + checks + " native-validation=false target-modified=false");
        }
        finally {
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
    }

    private static String completed(Path root, AttachmentPreparation.Plan plan, boolean partial) throws Exception {
        Files.writeString(plan.sidecar(), "fixture sidecar " + plan.sidecar().getFileName());
        Files.writeString(plan.invocation().operation().source(), "fixture synthetic source");
        Path captured = Files.createTempFile(root, "captured-", ".json");
        ExportArtifactHashBindingFixtures.write(new ExportArtifactHashBindingFixtures.Pair(root, captured,
            plan.exportInput(), plan.sidecar(), plan.invocation().operation().source()), partial);
        String report = Files.readString(captured);
        Files.delete(captured);
        return report;
    }

    @FunctionalInterface private interface Action { void run() throws Exception; }
    private static void rejects(Action action) throws Exception {
        try { action.run(); throw new AssertionError("unsafe preparation accepted"); }
        catch (IOException | CancellationException expected) { checks++; }
    }
    private static void equal(Object expected, Object actual) {
        if (!expected.equals(actual)) throw new AssertionError("expected " + expected + " but got " + actual);
        checks++;
    }
}
