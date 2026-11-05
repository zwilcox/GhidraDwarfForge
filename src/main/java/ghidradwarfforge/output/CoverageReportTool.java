package ghidradwarfforge.output;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/** Standalone read-only CLI. Opens selected reports only; never their referenced artifacts. */
public final class CoverageReportTool {
    private CoverageReportTool() { }
    private static final String USAGE = "Usage: CoverageReportTool --report FILE [--summary | --function 0xELF_ENTRY | --before FILE]\n" +
        "Default: summary and per-function tab-separated rows. --function: bounded evidence details.\n" +
        "--before: compare reported function/source/variable/type evidence with an earlier report; identity limitations are explicit.\n" +
        "Exit codes: 0 displayed (not validation/semantic equivalence), 1 read/output error, 2 incomparable, 11 cancelled, 64 usage.\n";

    public static void main(String[] args) {
        var out = new PrintWriter(System.out, true, StandardCharsets.UTF_8);
        var err = new PrintWriter(System.err, true, StandardCharsets.UTF_8);
        System.exit(run(args, out, err, () -> Thread.currentThread().isInterrupted()));
    }

    static int run(String[] args, PrintWriter out, PrintWriter err, BooleanSupplier cancelled) {
        try {
            if (args.length == 1 && args[0].equals("--help")) { out.print(USAGE); check(cancelled, out); return 0; }
            var options = new HashMap<String, String>();
            for (int index = 0; index < args.length; index++) {
                String key = args[index];
                boolean encoded = key.equals("--report-utf8-base64") || key.equals("--before-utf8-base64");
                if (encoded) key = key.substring(0, key.indexOf("-utf8-base64"));
                if (!java.util.Set.of("--report", "--before", "--function", "--summary").contains(key) || options.containsKey(key)) {
                    throw new IllegalArgumentException("unknown or repeated option: " + key);
                }
                String value = "";
                if (!key.equals("--summary")) {
                    if (++index == args.length) throw new IllegalArgumentException("missing value for " + key);
                    value = encoded ? AttachmentPathArgument.decode(args[index]) : args[index];
                    if (value.isEmpty()) throw new IllegalArgumentException("empty value for " + key);
                }
                options.put(key, value);
            }
            if (!options.containsKey("--report") ||
                    java.util.stream.Stream.of("--summary", "--function", "--before").filter(options::containsKey).count() > 1) {
                throw new IllegalArgumentException("select one report and at most one display/comparison mode");
            }
            Long selected = null;
            if (options.containsKey("--function")) {
                String value = options.get("--function");
                if (!value.matches("0x[0-9a-fA-F]{1,16}")) throw new IllegalArgumentException("function must be an ELF-link-time hexadecimal entry");
                selected = Long.parseUnsignedLong(value.substring(2), 16);
                if (selected < 0) throw new IllegalArgumentException("function outside supported address domain");
            }
            var report = ExportReportClaims.readWithCoverage(Path.of(options.get("--report")), cancelled);
            if (options.containsKey("--before")) {
                var before = ExportReportClaims.readWithCoverage(Path.of(options.get("--before")), cancelled);
                out.println("Function/source/variable/type evidence comparison. Reported claims only; no artifact validation.");
                out.println("Change\tELF function entry\tDetail");
                var result = CoverageComparison.compare(before, report, change -> {
                    out.println(change.kind() + "\t0x" + Long.toHexString(change.function()) + "\t" + safe(change.detail()));
                    check(cancelled, out);
                }, cancelled);
                out.println(result.comparable() ? "Comparison: matching reported binary/profile" : "Comparison: INCOMPARABLE");
                for (String reason : result.reasons()) out.println(safe(reason));
                if (result.comparable()) out.println("Reported changes: " + result.changes() + "; identity limitations above remain applicable.");
                check(cancelled, out);
                return result.comparable() ? 0 : 2;
            }
            if (report.coverage() == null) {
                out.println("Coverage: UNAVAILABLE (schema one). No zero coverage is inferred.");
                check(cancelled, out);
                return 0;
            }
            out.println("Reported coverage only; no referenced artifact was opened or independently validated.");
            var profile = report.coverage().profile();
            var display = new CoverageReportClaims(new CoverageReportJson.Profile(safe(profile.languageId()),
                safe(profile.compilerSpecId())), report.coverage().coverage());
            out.println(CoveragePresentation.summary(display, report.claims().status().name())
                .replace("Select a function for provenance and omission reasons. Save report retains all evidence.",
                    "Use --function 0xENTRY for provenance and omission reasons. The selected JSON retains complete evidence."));
            if (options.containsKey("--summary")) { check(cancelled, out); return 0; }
            boolean found = selected == null;
            if (selected == null) out.println(String.join("\t", CoveragePresentation.COLUMNS));
            for (var function : report.coverage().coverage().functions()) {
                check(cancelled, out);
                if (selected != null) {
                    if (function.function().address() == selected) {
                        // Preserve readable line breaks, neutralize terminal control codes.
                        for (String line : CoveragePresentation.details(function).split("\n", -1)) out.println(safe(line));
                        found = true;
                    }
                }
                else {
                    for (int column = 0; column < CoveragePresentation.COLUMNS.length; column++) {
                        if (column != 0) out.print('\t');
                        out.print(safe(CoveragePresentation.cell(function, column)));
                    }
                    out.println();
                }
            }
            if (!found) throw new IllegalArgumentException("no exported function at selected ELF entry");
            check(cancelled, out);
            return 0;
        }
        catch (CancellationException cancelledRun) { err.println("Coverage display cancelled; preceding output may be incomplete."); return 11; }
        catch (IllegalArgumentException usage) { err.println(safe(usage.getMessage())); err.print(USAGE); return 64; }
        catch (IOException | java.io.UncheckedIOException failure) {
            err.println("Coverage report error: " + safe(failure.getMessage()));
            return 1;
        }
        finally { out.flush(); err.flush(); }
    }

    private static void check(BooleanSupplier cancelled, PrintWriter out) {
        if (cancelled.getAsBoolean()) throw new CancellationException();
        if (out.checkError()) throw new java.io.UncheckedIOException(new IOException("output stream failed"));
    }

    /** Keep names/diagnostics in one TSV cell and prevent ANSI/bidi controls in terminals. */
    static String safe(String text) {
        if (text == null) return "";
        var result = new StringBuilder();
        text.codePoints().forEach(value -> {
            if (value == '\\') result.append("\\\\");
            else if (value == '\n') result.append("\\n");
            else if (value == '\r') result.append("\\r");
            else if (value == '\t') result.append("\\t");
            else if (Character.isISOControl(value) || Character.getType(value) == Character.FORMAT ||
                    value == 0x2028 || value == 0x2029) result.append(String.format("\\u%04x", value));
            else result.appendCodePoint(value);
        });
        return result.toString();
    }
}
