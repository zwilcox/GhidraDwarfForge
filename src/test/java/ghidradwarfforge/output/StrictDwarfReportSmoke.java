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
        // Git may check out this retained text fixture with CRLF on Windows.
        // Check those original bytes above, then construct each line-ending
        // variant from LF so CRLF never becomes the malformed CRCRLF.
        clean = clean.replace("\r\n", "\n");
        StrictDwarfReport.inspect(clean, false);
        checks++;
        StrictDwarfReport.inspect(clean.replace("\n", "\r\n"), false);
        checks++;
        reject(clean.replace("\n", "\r\r\n"));
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
        corruptCompleteReport(clean);
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

    private static void corruptCompleteReport(String clean) throws Exception {
        // Each corruption starts with the retained real checker output. Keeping
        // the rest complete proves that one contradictory or duplicated section
        // cannot be hidden behind the other apparently successful summaries.
        reject(null);
        reject(clean + " ".repeat(32 * 1024 * 1024));
        reject(clean + "HARMLESS ERROR COUNT: 0\nHARMLESS ERROR COUNT: 0\n");
        reject(clean.replace("1 Compilers detected:", "0 Compilers detected:")
            .replace("1 Compilers verified:", "0 Compilers verified:"));
        for (String heading : List.of("*** ERRORS PER COMPILER ***", "*** TOTAL ERRORS FOR ALL COMPILERS ***")) {
            reject(clean.replace(heading, heading + "\n" + heading));
        }
        reject(clean.replace("*** ERRORS PER COMPILER ***", "temporary_section_marker")
            .replace("*** TOTAL ERRORS FOR ALL COMPILERS ***", "*** ERRORS PER COMPILER ***")
            .replace("temporary_section_marker", "*** TOTAL ERRORS FOR ALL COMPILERS ***"));
        String lateCompilerHeader = clean.replace("*** ERRORS PER COMPILER ***", "")
            .replace("*** TOTAL ERRORS FOR ALL COMPILERS ***",
                "*** ERRORS PER COMPILER ***\n*** TOTAL ERRORS FOR ALL COMPILERS ***");
        reject(lateCompilerHeader);
        var categories = Pattern.compile("(?m)^[a-z_]+[ \\t]+[0-9]+[ \\t]+[0-9]+$").matcher(clean);
        int duplicated = 0;
        while (categories.find()) {
            reject(clean.substring(0, categories.end()) + "\n" + categories.group() + clean.substring(categories.end()));
            duplicated++;
        }
        require(duplicated == 44);
        reject(clean.replaceFirst("\\*\\* Summarize \\*\\*\\s+199", "** Summarize ** 200"));
        reject(clean.replaceFirst("harmless_errors[ \\t]+0[ \\t]+0", "harmless_errors 0 1"));
        String zeroChecks = clean.replaceAll("(?m)^([a-z_]+)[ \\t]+[0-9]+[ \\t]+0$", "$1 0 0")
            .replaceAll("(?m)^\\*\\* Summarize \\*\\*[ \\t]+[0-9]+[ \\t]+0$", "** Summarize ** 0 0");
        require(!zeroChecks.equals(clean));
        reject(zeroChecks);
        reject(clean + "Number of TAG records 4\n");
        reject(clean + "incomplete trailing record\n");
        int tail = clean.indexOf("Number of TAG records");
        require(tail > 0);
        reject(clean + clean.substring(tail));
        reject(clean.substring(0, tail) + "Number of TAG records 0\nNumber of distinct TAGs in object 0\n");
        // A corrupt input must not poison the next independent report.
        var after = StrictDwarfReport.inspect(clean, false);
        require(after.compilers() == 1 && after.checkTables() == 2 && after.frameDiagnostics().isEmpty());
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
