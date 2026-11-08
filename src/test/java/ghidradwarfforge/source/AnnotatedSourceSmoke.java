package ghidradwarfforge.source;

import java.nio.charset.StandardCharsets;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;
import com.google.gson.JsonParser;
import ghidradwarfforge.source.AnnotatedSourceFile.Insertion;
import ghidradwarfforge.source.SyntheticSourceFile.FunctionText;
import ghidradwarfforge.source.SyntheticSourceFile.RelativeLine;
import ghidradwarfforge.dwarf.Dwarf5LineTable;
import ghidradwarfforge.coverage.SourceCoverageIndex;
import ghidradwarfforge.coverage.SourceCoverage;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange;

/** Removing only inserted rows must recover the exact input text and every old mapping. */
public final class AnnotatedSourceSmoke {
    private static int negatives;

    private AnnotatedSourceSmoke() {
    }

    private static void reject(Runnable operation) {
        try {
            operation.run();
            throw new AssertionError("invalid annotation composition accepted");
        }
        catch (IllegalArgumentException expected) {
            negatives++;
        }
    }

    private static void verify(SyntheticSourceFile input, AnnotatedSourceFile.Result result) {
        var source = result.source();
        String[] lines = new String(source.utf8(), StandardCharsets.UTF_8).split("\n", -1);
        var inserted = new HashSet<>(result.annotationLines());
        if (inserted.size() != result.annotationLines().size()) throw new AssertionError("duplicate inserted row");
        var inverse = new HashMap<Integer, Integer>();
        var restored = new StringBuilder();
        int originalLine = 0;
        for (int index = 0; index < lines.length - 1; index++) {
            if (inserted.contains(index + 1)) {
                if (!lines[index].startsWith("/* ") || !lines[index].endsWith(" */")) {
                    throw new AssertionError("non-comment insertion");
                }
            }
            else {
                inverse.put(index + 1, ++originalLine);
                restored.append(lines[index]).append('\n');
            }
        }
        if (!Arrays.equals(input.utf8(), restored.toString().getBytes(StandardCharsets.UTF_8))) {
            throw new AssertionError("original source bytes changed");
        }
        if (source.mappedLines().size() != input.mappedLines().size()) throw new AssertionError("new executable rows");
        for (int index = 0; index < source.mappedLines().size(); index++) {
            var before = input.mappedLines().get(index);
            var after = source.mappedLines().get(index);
            if (!Integer.valueOf(before.line()).equals(inverse.get(after.line())) || !before.addresses().equals(after.addresses())) {
                throw new AssertionError("source address evidence changed");
            }
        }
        if (source.functions().size() != input.functions().size() || source.functionTokens().size() != input.functionTokens().size()) {
            throw new AssertionError("function evidence count changed");
        }
        for (int index = 0; index < source.functions().size(); index++) {
            var before = input.functions().get(index);
            var after = source.functions().get(index);
            if (!before.equals(new SyntheticSourceFile.FunctionLines(after.name(), after.address(),
                    inverse.get(after.startLine()), inverse.get(after.endLine()), after.decompiled(),
                    after.failureDiagnostic(), after.omissionDiagnostic()))) {
                throw new AssertionError("function source boundaries/disposition changed");
            }
        }
        for (int index = 0; index < source.functionTokens().size(); index++) {
            var before = input.functionTokens().get(index);
            var after = source.functionTokens().get(index);
            var restoredTokens = new ArrayList<SyntheticSourceFile.SourceLine>();
            for (var line : after.lines()) {
                Integer oldLine = inverse.get(line.line());
                if (oldLine == null) throw new AssertionError("comment acquired executable token evidence");
                restoredTokens.add(new SyntheticSourceFile.SourceLine(oldLine, line.addresses()));
            }
            if (!before.equals(new SyntheticSourceFile.FunctionTokens(after.name(), after.address(), restoredTokens))) {
                throw new AssertionError("function token evidence changed");
            }
        }
    }

    private static void verifyPayload(AnnotatedSourceFile.Result result, List<Insertion> displayedOrder) {
        String[] lines = new String(result.source().utf8(), StandardCharsets.UTF_8).split("\n", -1);
        int index = 0;
        for (Insertion insertion : displayedOrder) {
            String heading = lines[result.annotationLines().get(index++) - 1];
            if (!decodeComment(heading).equals(insertion.label())) throw new AssertionError("annotation label changed");
            var recovered = new StringBuilder();
            long rows = insertion.text().chars().filter(value -> value == '\n').count() + 1;
            for (long row = 0; row < rows; row++) recovered.append(decodeComment(lines[result.annotationLines().get(index++) - 1]));
            if (!recovered.toString().equals(insertion.text())) throw new AssertionError("annotation payload/line separators changed");
        }
        if (index != result.annotationLines().size()) throw new AssertionError("unaccounted annotation rows");
    }

    private static String decodeComment(String line) {
        String encoded = line.substring(3, line.length() - 3);
        return JsonParser.parseString("\"" + encoded.replace("\"", "\\\"") + "\"").getAsString();
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 1) throw new IllegalArgumentException("[output.c]");
        var input = SyntheticSourceFile.build("annotation fixture", "test", List.of(
            new FunctionText("first", 0x1000, "int first(int input)\n{\n    return input + 1;\n}\n", null,
                List.of(new RelativeLine(3, List.of(0x1004L, 0x1104L)))),
            new FunctionText("alias", 0x1000, "int alias(void) { return 2; }\n", null,
                List.of(new RelativeLine(1, List.of(0x1000L)))),
            new FunctionText("failed", 0x2000, null, "native failure")));
        byte[] before = input.utf8();
        int tokenLine = input.functionTokens().stream().filter(function -> function.name().equals("first"))
            .findFirst().orElseThrow().lines().getFirst().line();
        var first = new Insertion("b", "Ghidra listing EOL */ λ", "closing */\r\nsecond λ\n", tokenLine, 0x1104L);
        var second = new Insertion("a", "Ghidra listing PRE", "*/\n#error escaped\n/*", tokenLine, 0x1004L);
        var catalog = new Insertion("c", "Ghidra listing comment at unmapped address", "failed-function note", 0, null);
        var insertions = List.of(first, second, catalog);
        var result = AnnotatedSourceFile.compose(input, insertions, 100_000, () -> false);
        verify(input, result);
        verifyPayload(result, List.of(second, first, catalog));
        var symbols = List.of(new FunctionSymbol("alias", 0x1000, 8),
            new FunctionSymbol("first", 0x1000, List.of(new FunctionRange(0x1000, 8), new FunctionRange(0x1100, 8))),
            new FunctionSymbol("failed", 0x2000, 8));
        for (int width : new int[] {4, 8}) {
            for (var order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                var baseline = Dwarf5LineTable.buildWithPlan("fixture.dbg.c", "/fixture", width, order, symbols, input.mappedLines());
                var emitted = Dwarf5LineTable.buildWithPlan("fixture.dbg.c", "/fixture", width, order, symbols, result.source().mappedLines());
                if (baseline.sequences().size() != emitted.sequences().size()) throw new AssertionError("line sequence count changed");
                for (int index = 0; index < emitted.sequences().size(); index++) {
                    var beforeSequence = baseline.sequences().get(index);
                    var afterSequence = emitted.sequences().get(index);
                    if (beforeSequence.start() != afterSequence.start() || beforeSequence.endExclusive() != afterSequence.endExclusive() ||
                            !beforeSequence.rows().stream().map(Dwarf5LineTable.LineRow::address).toList()
                                .equals(afterSequence.rows().stream().map(Dwarf5LineTable.LineRow::address).toList()) ||
                            afterSequence.rows().stream().anyMatch(row -> result.annotationLines().contains(row.line()))) {
                        throw new AssertionError("annotation changed emitted address visibility");
                    }
                }
                var beforeIndex = new SourceCoverageIndex(baseline, () -> false);
                var afterIndex = new SourceCoverageIndex(emitted, () -> false);
                var starts = List.of(0x1000L, 0x1004L, 0x1100L, 0x1104L);
                var beforeTokens = input.functionTokens().stream().filter(function -> function.name().equals("first")).findFirst().orElseThrow().lines();
                var afterTokens = result.source().functionTokens().stream().filter(function -> function.name().equals("first")).findFirst().orElseThrow().lines();
                var counts = beforeIndex.measure(symbols.get(1), starts, beforeTokens, () -> false);
                if (!counts.equals(new SourceCoverage(4, 2, 3)) ||
                        !counts.equals(afterIndex.measure(symbols.get(1), starts, afterTokens, () -> false))) {
                    throw new AssertionError("annotation changed coverage populations");
                }
            }
        }
        var reordered = AnnotatedSourceFile.compose(input, List.of(catalog, second, first), 100_000, () -> false);
        if (!Arrays.equals(result.source().utf8(), reordered.source().utf8()) ||
                !result.annotationLines().equals(reordered.annotationLines())) throw new AssertionError("input order changed composition");
        var unchanged = AnnotatedSourceFile.compose(input, List.of(), before.length, () -> false);
        verify(input, unchanged);
        if (!Arrays.equals(before, unchanged.source().utf8()) || !unchanged.annotationLines().isEmpty()) {
            throw new AssertionError("empty insertion set changes source");
        }
        verify(input, AnnotatedSourceFile.compose(input, insertions, result.source().utf8().length, () -> false));
        reject(() -> AnnotatedSourceFile.compose(input, insertions, result.source().utf8().length - 1, () -> false));
        reject(() -> AnnotatedSourceFile.compose(input, List.of(), before.length - 1, () -> false));
        reject(() -> AnnotatedSourceFile.compose(input, List.of(first, first), 100_000, () -> false));
        reject(() -> AnnotatedSourceFile.compose(input,
            List.of(new Insertion("bad", "bad", "text", tokenLine, 0x7777L)), 100_000, () -> false));
        int declaration = input.functions().stream().filter(function -> function.name().equals("first"))
            .findFirst().orElseThrow().startLine();
        reject(() -> AnnotatedSourceFile.compose(input,
            List.of(new Insertion("bad", "bad", "text", declaration, 0x1000L)), 100_000, () -> false));
        reject(() -> AnnotatedSourceFile.compose(new SyntheticSourceFile(new byte[] {(byte) 0xc3}, List.of(), List.of()),
            List.of(), 100, () -> false));
        reject(() -> AnnotatedSourceFile.compose(new SyntheticSourceFile("x\r\n".getBytes(StandardCharsets.UTF_8), List.of(), List.of()),
            List.of(), 100, () -> false));
        reject(() -> AnnotatedSourceFile.compose(new SyntheticSourceFile(before, input.functions(),
            List.of(new SyntheticSourceFile.SourceLine(9999, List.of(1L))), input.functionTokens()), List.of(), 100_000, () -> false));
        var failed = SyntheticSourceFile.build("failed fixture", "test", List.of(new FunctionText("failed", 1, null, "native failure")));
        var failedResult = AnnotatedSourceFile.compose(failed, List.of(catalog), 100_000, () -> false);
        verify(failed, failedResult);
        if (!failedResult.source().mappedLines().isEmpty() || failedResult.source().functions().getFirst().decompiled()) {
            throw new AssertionError("failed function acquired source evidence");
        }
        var calls = new AtomicInteger();
        AnnotatedSourceFile.compose(input, insertions, 100_000, () -> { calls.incrementAndGet(); return false; });
        for (int point = 1; point <= calls.get(); point++) {
            int cancelAt = point;
            var current = new AtomicInteger();
            try {
                AnnotatedSourceFile.compose(input, insertions, 100_000, () -> current.incrementAndGet() == cancelAt);
                throw new AssertionError("cancellation ignored: " + point);
            }
            catch (CancellationException expected) {
                if (current.get() != cancelAt) throw new AssertionError("cancellation delayed");
            }
        }
        if (!Arrays.equals(before, input.utf8())) throw new AssertionError("input source changed");
        if (args.length == 1) Files.write(Path.of(args[0]), result.source().utf8());
        System.out.println("annotated-source=PASS annotation-lines=" + result.annotationLines().size() +
            " preserved-mapped-rows=" + input.mappedLines().size() + " rejected=" + negatives +
            " cancellation-points=" + calls.get());
    }
}
