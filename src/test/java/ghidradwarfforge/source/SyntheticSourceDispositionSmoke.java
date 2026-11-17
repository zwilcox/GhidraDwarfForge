package ghidradwarfforge.source;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import ghidradwarfforge.source.SyntheticSourceFile.*;

/** Failed/omitted text has no executable rows; source and token evidence stay consistent. */
public final class SyntheticSourceDispositionSmoke {
    private static int checks;

    public static void main(String[] args) { run(); }

    static void run() {
        dispositions();
        normalizedRows();
        unavailableRows();
        frozenTokens();
        System.out.println("synthetic-source-dispositions=PASS checks=" + checks);
    }

    private static void dispositions() {
        // Each public disposition is independent: exactly one must explain the
        // function's source, even when the strings themselves are empty.
        for (int mask = 0; mask < 8; mask++) {
            String c = (mask & 1) == 0 ? null : "int fixture(void) { return 1; }";
            String failed = (mask & 2) == 0 ? null : "decompiler failed";
            String omitted = (mask & 4) == 0 ? null : "analyst omitted";
            if (Integer.bitCount(mask) == 1) {
                var source = SyntheticSourceFile.build("fixture", "language", List.of(
                    new FunctionText("fixture", 0x1000, c, failed, List.of(), omitted)));
                require(source.functions().getFirst().decompiled() == (c != null), "source disposition agrees with metadata");
                require(source.mappedLines().size() == (c != null ? 1 : 0), "only available declaration has an address");
            }
            else rejects(() -> new FunctionText("fixture", 0x1000, c, failed, List.of(), omitted));
            for (boolean decompiled : List.of(false, true)) {
                boolean valid = decompiled ? failed == null && omitted == null : (failed == null) != (omitted == null);
                if (valid) {
                    new FunctionLines("fixture", 0x1000, 8, 8, decompiled, failed, omitted);
                    checks++;
                }
                else rejects(() -> new FunctionLines("fixture", 0x1000, 8, 8, decompiled, failed, omitted));
            }
        }
        for (String blank : List.of("", " ", "\t\n")) {
            rejects(() -> FunctionText.omitted("fixture", 0, blank));
            rejects(() -> new FunctionLines("fixture", 0, 8, 8, false, null, blank));
        }
        var tokens = List.of(new RelativeLine(1, List.of(0x1000L)));
        rejects(() -> new FunctionText("fixture", 0x1000, null, "failed", tokens, null));
        rejects(() -> new FunctionText("fixture", 0x1000, null, null, tokens, "omitted"));
        rejects(() -> new RelativeLine(0, List.of(0L)));
        rejects(() -> new RelativeLine(1, List.of()));
        rejects(() -> new FunctionText(null, 0, "", null));
        rejects(() -> new FunctionText(" ", 0, "", null));
        rejects(() -> new FunctionText("fixture", -1, "", null));
    }

    private static void normalizedRows() {
        String c = "/* helper(\r\n * helper(\r\n */\r\n// helper(\r\nint unrelated;\r\n" +
            "int helper(void)\r\n{\r\n    return 1;\r\n}\r\n\t ";
        var function = new FunctionText("helper", 0x1000, c, null, List.of(
            new RelativeLine(8, List.of(0x1008L, 0x1004L, 0x1008L)),
            new RelativeLine(8, List.of(0x100cL)),
            new RelativeLine(10, List.of(0x1010L))));
        var source = SyntheticSourceFile.build("firmware λ*/\r\n", "language\rname", List.of(function));
        String text = new String(source.utf8(), StandardCharsets.UTF_8);
        require(text.contains("Program: firmware λ* /  ") && text.contains("Ghidra language: language name"),
            "Unicode header remains UTF-8 and escapes comment terminators/newlines");
        require(!text.contains("\r") && text.endsWith("    return 1;\n}\n\n"), "C normalization retains interior layout and one trailing blank separator");
        require(source.functions().getFirst().startLine() == 8 && source.functions().getFirst().endLine() == 16,
            "function extent counts normalized physical lines");
        require(source.mappedLines().equals(List.of(new SourceLine(13, List.of(0x1000L)),
            new SourceLine(15, List.of(0x1004L, 0x1008L, 0x100cL)))),
            "comments/unrelated declaration get no address; duplicate token rows merge; out-of-text row is omitted");
        require(source.functionTokens().getFirst().lines().equals(List.of(
            new SourceLine(15, List.of(0x1004L, 0x1008L)), new SourceLine(15, List.of(0x100cL)))),
            "token provenance excludes synthetic declaration and out-of-text rows");
    }

    private static void unavailableRows() {
        var input = new ArrayList<>(List.of(
            new FunctionText("zeta", 0x1000, " ", null),
            new FunctionText("alpha", 0x1000, "\t\r\n", null),
            new FunctionText("failed", 0x2000, null, "problem */\r\n"),
            FunctionText.omitted("omitted", 0x3000, "analyst */\r\nchoice"),
            new FunctionText("empty", 0x4000, "", null)));
        var source = SyntheticSourceFile.build(null, " ", input);
        Collections.reverse(input);
        var second = SyntheticSourceFile.build(null, " ", input);
        require(Arrays.equals(source.utf8(), second.utf8()) && source.functions().equals(second.functions()) &&
            source.functionTokens().equals(second.functionTokens()), "input order does not change names, boundaries, bytes or provenance");
        require(source.functions().stream().map(FunctionLines::name).toList().equals(List.of("alpha", "zeta", "failed", "omitted", "empty")),
            "equal addresses have deterministic name ordering");
        require(source.mappedLines().isEmpty() && source.functionTokens().stream().allMatch(row -> row.lines().isEmpty()),
            "empty, failed and intentionally omitted functions never invent executable mappings");
        String text = new String(source.utf8(), StandardCharsets.UTF_8);
        require(text.contains("Program: <unavailable>") && text.contains("Ghidra language: <unavailable>") &&
            text.contains("problem * /  ") && text.contains("analyst * /  choice"), "missing metadata and diagnostics render safely");
        for (var function : source.functions()) require(function.startLine() == function.endLine(), "each empty or unavailable body occupies one line");
    }

    private static void frozenTokens() {
        var addresses = new ArrayList<>(List.of(0x1000L));
        var rows = new ArrayList<>(List.of(new SourceLine(8, addresses)));
        var snapshot = new FunctionTokens("fixture", 0x1000, rows);
        addresses.add(0x2000L); rows.clear();
        require(snapshot.lines().equals(List.of(new SourceLine(8, List.of(0x1000L)))), "token snapshot detaches both mutable input levels");
        try { snapshot.lines().getFirst().addresses().add(0x3000L); throw new AssertionError("token addresses are mutable"); }
        catch (UnsupportedOperationException expected) { checks++; }
        rejects(() -> new FunctionTokens(null, 0, List.of()));
        rejects(() -> new FunctionTokens(" ", 0, List.of()));
        rejects(() -> new FunctionTokens("fixture", -1, List.of()));
        rejects(() -> new FunctionTokens("fixture", 0, null));
        var source = SyntheticSourceFile.build("fixture", "language", List.of());
        byte[] original = source.utf8();
        byte[] returned = source.utf8(); returned[0] = 0;
        require(Arrays.equals(source.utf8(), original), "callers cannot modify source bytes through accessor");
    }

    private static void rejects(Runnable action) {
        try { action.run(); throw new AssertionError("inconsistent source evidence accepted"); }
        catch (IllegalArgumentException expected) { checks++; }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }
}
