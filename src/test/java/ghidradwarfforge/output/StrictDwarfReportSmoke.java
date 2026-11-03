package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Pattern;

/** Retained real checker output and corruption controls, not fabricated passing summaries. */
public final class StrictDwarfReportSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Path fixtures = Path.of(args[0]);
        String clean = Files.readString(fixtures.resolve("clean-2.3.2.txt"));
        var analysis = StrictDwarfReport.inspect(clean, false);
        require(analysis.compilers() == 1 && analysis.checkTables() == 2 && analysis.frameDiagnostics().isEmpty());
        StrictDwarfReport.inspect(clean.replace("\n", "\r\n"), false);
        checks++;
        reject(Files.readString(fixtures.resolve("exit-zero-errors-20210528.txt")));
        reject("");
        reject(clean + "\0");
        reject(clean + "warning: an unexplained diagnostic\n");
        reject(clean + "DW_DLE_BOGUS\n");
        reject(clean + clean);
        reject(clean.replaceFirst("errors =     0,", "errors =     1,"));
        reject(clean.replaceFirst("(line_table\\s+[0-9]+\\s+)0", "$14"));
        reject(clean.replaceFirst("(\\*\\* Summarize \\*\\*\\s+[0-9]+\\s+)0", "$11"));
        reject(clean.replaceFirst("(line_table\\s+)[0-9]+", "$1unknown"));
        reject(clean.replaceFirst("1 Compilers verified", "2 Compilers verified"));
        reject(clean.replaceFirst("1 Compilers verified", "9999999999999999999999999 Compilers verified"));
        reject(clean.replaceFirst("Number of distinct TAGs in object\\s+4", "Number of distinct TAGs in object 5"));
        reject(clean.replaceFirst("Number of TAG records\\s+4", "Number of TAG records 3"));
        reject(clean.replaceFirst("\\[    3\\] 0x002e", "[    2] 0x002e"));
        reject(clean.replaceFirst("locations", "unknown_category"));
        reject(clean.replaceFirst("DWARF CHECK RESULT", "DWARF CHECK RESULT\nDWARF CHECK RESULT"));
        var rows = Pattern.compile("(?m)^[a-z_]+\\s+[0-9]+\\s+[0-9]+\\n").matcher(clean);
        int removed = 0;
        while (rows.find()) {
            reject(clean.substring(0, rows.start()) + clean.substring(rows.end()));
            removed++;
        }
        require(removed == 44);
        // Every line-boundary prefix before the last complete usage row fails,
        // even when it includes apparently successful compiler/total summaries.
        int endOfLastRecord = clean.lastIndexOf("[    3]");
        for (int index = clean.indexOf('\n'); index < endOfLastRecord; index = clean.indexOf('\n', index + 1)) {
            if (index < 0) break;
            reject(clean.substring(0, index + 1));
        }
        // Extra callers supply real reports from fresh/retained production
        // exports, including original-only reports with zero DWARF producers.
        for (String argument : List.of(args).subList(1, args.length)) {
            Path path = Path.of(argument);
            boolean original = path.getFileName().toString().contains("original");
            var observed = StrictDwarfReport.inspect(Files.readString(path), original);
            System.out.println("strict-report-observed=" + path + " compilers=" + observed.compilers() +
                " frame-diagnostics-requiring-proof=" + observed.frameDiagnostics().size());
            checks++;
            if (!observed.frameDiagnostics().isEmpty()) {
                String report = Files.readString(path);
                String diagnostic = observed.frameDiagnostics().getFirst();
                reject(report.replaceFirst(Pattern.quote(diagnostic), ""), original);
                reject(report + diagnostic + "\n", original);
                reject(report.replace("DEBUG_FRAME_LENGTH_NOT_MULTIPLE", "OTHER_ERROR"), original);
            }
        }
        System.out.println("strict-dwarf-report-smoke=PASS checks=" + checks);
    }

    private static void reject(String text) throws Exception { reject(text, false); }

    private static void reject(String text, boolean original) throws Exception {
        try { StrictDwarfReport.inspect(text, original); }
        catch (IOException expected) { checks++; return; }
        throw new AssertionError("accepted corrupt/incomplete report: " + text.substring(0, Math.min(180, text.length())));
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("unexpected real report analysis");
        checks++;
    }
}
