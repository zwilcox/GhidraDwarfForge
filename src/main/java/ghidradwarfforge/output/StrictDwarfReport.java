package ghidradwarfforge.output;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Interprets the complete -ka -ki -kd report from the pinned libdwarf 2.3.2
 * checker. An Analysis with frame diagnostics is NOT a successful validation:
 * the caller must independently corroborate their exact multiplicity, ELF
 * identity and frame bytes against the original. Process completion, stderr,
 * tool/configuration provenance and unchanged input binding are also separate.
 */
final class StrictDwarfReport {
    private static final int MAX_TEXT_CHARS = 32 * 1024 * 1024;
    private static final Pattern FRAME = Pattern.compile(
        "\\*\\*\\* DWARF CHECK: DW_DLE_DEBUG_FRAME_LENGTH_NOT_MULTIPLE " +
        "len=0x[0-9a-f]+, len size=0x[0-9a-f]+, extn size=0x[0-9a-f]+, " +
        "totl length=0x[0-9a-f]+, addr size=0x[0-9a-f]+, mod=0x[0-9a-f]+ " +
        "must be zero in (?:fde|cie), offset 0x[0-9a-f]+\\. \\*\\*\\*");
    private static final Pattern DIAGNOSTIC = Pattern.compile(
        "\\*\\*\\* DWARF CHECK:|\\bDW_DLE_|\\b(?:warning|error|fatal):", Pattern.CASE_INSENSITIVE);
    private static final Set<String> CATEGORIES = Set.of(
        "pubname_attr", "attr_tag", "attr_formclass", "tag_tree", "type_offset",
        "decl_file", "ranges", "line_table", "fde_table", "aranges", "names",
        "frames", "locations", "harmless_errors", "abbreviations", "dwarf_constants",
        "debug_info_gaps", "forward_declarations", "self_references", "attr_encoding",
        "duplicated_attributes", "function_coverage");

    record Analysis(int compilers, int checkTables, List<String> frameDiagnostics) {
        Analysis { frameDiagnostics = List.copyOf(frameDiagnostics); }
    }
    private record Counts(long checks, long errors) { }

    private StrictDwarfReport() { }

    static Analysis inspect(String text, boolean original) throws IOException {
        require(text != null && !text.isBlank() && text.length() <= MAX_TEXT_CHARS && text.indexOf('\0') < 0,
            "empty, oversized or NUL-containing checker report");
        List<String> lines = text.lines().toList();
        List<String> frames = new ArrayList<>();
        for (String line : lines) {
            if (FRAME.matcher(line.strip()).matches()) frames.add(line.strip());
            else require(!DIAGNOSTIC.matcher(line).find(), "unclassified checker diagnostic");
        }
        var harmless = matches(text, "HARMLESS ERROR COUNT:\\s*([0-9]+)");
        require(harmless.isEmpty() ? frames.isEmpty() : harmless.size() == 1 && number(harmless.getFirst()) == frames.size(),
            "inconsistent harmless error count");
        long detected = singleNumber(text, "(?m)^\\s*([0-9]+) Compilers detected:\\s*$");
        long verified = singleNumber(text, "(?m)^\\s*([0-9]+) Compilers verified:\\s*$");
        require(detected == verified && verified >= (original ? 0 : 1) && verified <= 262144,
            "missing or inconsistent compiler completion");
        var errorStrings = matches(text, "(?m)^\\s*[0-9]+: errors\\s*=\\s*([0-9]+), .+$");
        require(errorStrings.size() == verified, "incomplete compiler error records");
        List<Long> errors = new ArrayList<>();
        long compilerErrors = 0;
        for (String error : errorStrings) {
            long value = number(error);
            compilerErrors = add(compilerErrors, value);
            errors.add(value);
        }
        require(compilerErrors == (verified == 0 ? 0 : frames.size()), "uncorroborated compiler errors");
        int perCompiler = uniqueLine(lines, "*** ERRORS PER COMPILER ***");
        int totalPosition = uniqueLine(lines, "*** TOTAL ERRORS FOR ALL COMPILERS ***");
        List<Integer> starts = new ArrayList<>();
        for (int index = 0; index < lines.size(); index++) {
            if (lines.get(index).strip().equals("DWARF CHECK RESULT")) starts.add(index);
        }
        require(starts.size() == verified + 1 && perCompiler < totalPosition &&
            (verified == 0 || (perCompiler < starts.getFirst() && starts.get(starts.size() - 2) < totalPosition)) &&
            totalPosition < starts.getLast(), "incomplete or misplaced check tables");
        errors.add((long) frames.size());
        var rowPattern = Pattern.compile("\\s*([a-z_]+)\\s+([0-9]+)\\s+([0-9]+)\\s*");
        var summaryPattern = Pattern.compile("\\s*\\*\\* Summarize \\*\\*\\s+([0-9]+)\\s+([0-9]+)\\s*");
        int lastTableEnd = -1;
        for (int table = 0; table < starts.size(); table++) {
            int start = starts.get(table);
            require(start + 1 < lines.size() && lines.get(start + 1).strip().replaceAll("\\s+", " ")
                .equals("<item> <checks> <errors>"), "malformed check table header");
            Map<String, Counts> rows = new HashMap<>();
            long checks = 0;
            boolean complete = false;
            for (int index = start + 2; index < lines.size(); index++) {
                var summary = summaryPattern.matcher(lines.get(index));
                if (summary.matches()) {
                    require(rows.keySet().equals(CATEGORIES), "missing or unexpected check categories");
                    require(checks > 0 && checks == number(summary.group(1)) &&
                        number(summary.group(2)) == errors.get(table) &&
                        rows.get("harmless_errors").errors() == errors.get(table), "inconsistent check totals");
                    complete = true;
                    lastTableEnd = index;
                    break;
                }
                var row = rowPattern.matcher(lines.get(index));
                require(row.matches(), "malformed or truncated check table");
                var counts = new Counts(number(row.group(2)), number(row.group(3)));
                require(rows.put(row.group(1), counts) == null, "duplicate check category");
                require(row.group(1).equals("harmless_errors") || counts.errors() == 0,
                    "checker category reports an uncorroborated error");
                checks = add(checks, counts.checks());
            }
            require(complete, "check table has no completed summary");
        }
        // Global checks can occur outside a compiler's scope. The retained
        // clean 2.3.2 report has function_coverage=20 per compiler and 21 total.
        // Require each table's own complete arithmetic, not equality between
        // counts that the checker does not define as equal.
        int tagStart = -1;
        for (int index = 0; index < lines.size(); index++) {
            if (lines.get(index).startsWith("Number of TAG records")) {
                require(tagStart == -1, "duplicate final tag report");
                tagStart = index;
            }
        }
        require(tagStart > lastTableEnd, "missing final tag report");
        String tail = String.join("\n", lines.subList(tagStart, lines.size()));
        long recordCount = singleNumber(tail, "(?m)^Number of TAG records\\s+([0-9]+)\\s*$");
        if (original && verified == 0 && recordCount == 0) {
            require(tail.strip().matches("Number of TAG records\\s+0"), "unexpected empty-original report tail");
        }
        else {
            long instances = singleNumber(tail, "(?m)^Number of distinct TAGs in object\\s+([0-9]+)\\s*$");
            var records = Pattern.compile("(?m)^\\[\\s*([0-9]+)\\]\\s+0x[0-9a-f]+\\s+DW_TAG_\\w+\\s+([0-9]+)\\s+[0-9.]+[ \\t]*$")
                .matcher(tail);
            long seen = 0;
            long uses = 0;
            int lastEnd = -1;
            Set<Long> indexes = new HashSet<>();
            while (records.find()) {
                require(indexes.add(number(records.group(1))), "duplicate final tag index");
                seen++;
                uses = add(uses, number(records.group(2)));
                lastEnd = records.end();
            }
            require(seen == recordCount && seen > 0 && uses == instances && lastEnd >= 0 &&
                tail.substring(lastEnd).isBlank(), "truncated or inconsistent final tag report");
        }
        return new Analysis((int) verified, starts.size(), frames);
    }

    private static int uniqueLine(List<String> lines, String wanted) throws IOException {
        int result = -1;
        for (int index = 0; index < lines.size(); index++) {
            if (lines.get(index).strip().equals(wanted)) {
                require(result == -1, "duplicate report summary");
                result = index;
            }
        }
        require(result >= 0, "missing report summary");
        return result;
    }

    private static List<String> matches(String text, String regex) {
        var result = new ArrayList<String>();
        var matcher = Pattern.compile(regex).matcher(text);
        while (matcher.find()) result.add(matcher.group(1));
        return result;
    }

    private static long singleNumber(String text, String regex) throws IOException {
        var values = matches(text, regex);
        require(values.size() == 1, "missing or repeated report counter");
        return number(values.getFirst());
    }

    private static long number(String text) throws IOException {
        try { return Long.parseLong(text); }
        catch (NumberFormatException invalid) { throw new IOException("checker counter exceeds supported range", invalid); }
    }

    private static long add(long first, long second) throws IOException {
        try { return Math.addExact(first, second); }
        catch (ArithmeticException invalid) { throw new IOException("checker counter sum exceeds supported range", invalid); }
    }

    private static void require(boolean condition, String message) throws IOException {
        if (!condition) throw new IOException(message);
    }
}
