package ghidradwarfforge.output;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/** Bounded plain-text view; reads the selected earlier report, never referenced artifacts. */
public final class CoverageComparisonPresentation {
    private static final int DISPLAY_LIMIT = 64 * 1024;
    private CoverageComparisonPresentation() { }

    public static String compare(String currentReport, Path earlier, BooleanSupplier cancelled) throws IOException {
        check(cancelled);
        var before = ExportReportClaims.readWithCoverage(earlier, cancelled);
        check(cancelled);
        // The captured current report was preflighted before publication. The same
        // strict decoder keeps compatibility and comparison admission in one place.
        byte[] bytes = currentReport.getBytes(StandardCharsets.UTF_8);
        check(cancelled);
        var current = ExportReportClaims.readWithCoverage(Path.of("captured-current-report"), cancelled,
            ignored -> new ByteArrayInputStream(bytes), ReportJsonReader.DEFAULT_LIMITS);
        return render(before, current, cancelled, DISPLAY_LIMIT);
    }

    static String render(ExportReportClaims.WithCoverage before, ExportReportClaims.WithCoverage after,
            BooleanSupplier cancelled, int limit) {
        if (limit < 1) throw new IllegalArgumentException("display limit must be positive");
        var text = new StringBuilder();
        var clipped = new boolean[1];
        var result = CoverageComparison.compare(before, after, change -> {
            check(cancelled);
            if (clipped[0]) return; // Keep counting and checking cancellation after display saturation.
            String line = change.kind() + "  function 0x" + Long.toHexString(change.function()) + "\n  " +
                CoverageReportTool.safe(change.detail()) + "\n";
            int length = Math.min(line.length(), limit - text.length());
            if (length > 0 && Character.isHighSurrogate(line.charAt(length - 1))) length--;
            text.append(line, 0, length);
            clipped[0] = length < line.length();
        }, cancelled);
        check(cancelled);
        var header = new StringBuilder("Earlier selected report → current export\nReported evidence only; no referenced artifact was opened or validated.\n");
        header.append(result.comparable() ? "Comparison: matching reported binary/profile\nReported changes: " + result.changes() + "\n" :
            "Comparison: INCOMPARABLE\n");
        for (String reason : result.reasons()) { check(cancelled); header.append(reason).append('\n'); }
        if (clipped[0]) header.append("Display limit reached. This view shows only a prefix of the changes. Use the report CLI for the complete comparison.\n");
        if (result.comparable() && result.changes() == 0) header.append("No differences in the compared evidence fields; the identity and evidence limitations above still apply.\n");
        check(cancelled);
        return header.append('\n').append(text).toString();
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("coverage comparison cancelled");
    }
}
