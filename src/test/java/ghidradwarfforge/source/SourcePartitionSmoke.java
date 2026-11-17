package ghidradwarfforge.source;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CancellationException;

import ghidradwarfforge.source.SyntheticSourceFile.FunctionLines;
import ghidradwarfforge.source.SyntheticSourceFile.FunctionText;
import ghidradwarfforge.source.SyntheticSourceFile.RelativeLine;
import ghidradwarfforge.source.SyntheticSourceFile.SourceLine;

/** Independent losslessness, source lookup, boundary and failure controls. */
public final class SourcePartitionSmoke {
    private SourcePartitionSmoke() { }

    public static void main(String[] args) {
        var functions = new ArrayList<FunctionText>();
        for (int index = 0; index < 23; index++) {
            long address = 0x1000L + 0x100L * index;
            String text = "int duplicate(void) {\n" +
                "    /* Unicode λ and literal quote \"; not a path */\n" +
                "    int value = 0;\n".repeat(index % 7 + 1) +
                "    return value;\n}\n";
            functions.add(new FunctionText("duplicate", address, text, null,
                List.of(new RelativeLine(3, List.of(address + 4, address + 0x40)))));
        }
        functions.add(new FunctionText("failed", 0x5000, null, "controlled failure"));
        functions.add(FunctionText.omitted("omitted", 0x6000, "intentional unavailable source"));
        var source = SyntheticSourceFile.build("fixture", "test", functions);
        byte[] before = source.utf8();
        String[] logical = new String(before, StandardCharsets.UTF_8).split("\n", -1);
        for (int target : new int[] { 1, 2, 7, 20, 73, 10000 }) {
            var plan = SourcePartitionPlan.build(source, target, () -> false);
            var repeat = SourcePartitionPlan.build(source, target, () -> false);
            var recovered = new StringBuilder();
            int expectedLine = 1;
            for (int index = 0; index < plan.parts().size(); index++) {
                var part = plan.parts().get(index);
                require(part.firstLogicalLine() == expectedLine, "partition gap or overlap");
                require(part.file() == index + 1, "file zero must remain reserved for index");
                require(Arrays.equals(part.utf8(), repeat.parts().get(index).utf8()), "nondeterministic bytes");
                String[] lines = new String(part.utf8(), StandardCharsets.UTF_8).split("\n", -1);
                require(lines[0].contains("Synthetic") && lines[1].contains("not recovered original"),
                    "partition lacks synthetic source identification");
                for (int original = part.firstLogicalLine(); original <= part.lastLogicalLine(); original++) {
                    var position = plan.locate(original);
                    require(position.file() == part.file(), "wrong file lookup");
                    require(lines[position.line() - 1].equals(logical[original - 1]), "wrong local line lookup");
                    recovered.append(lines[position.line() - 1]).append('\n');
                }
                require(part.oversized() == (part.lastLogicalLine() - part.firstLogicalLine() + 1 > target),
                    "oversized indivisible unit not reported");
                expectedLine = part.lastLogicalLine() + 1;
            }
            require(Arrays.equals(before, recovered.toString().getBytes(StandardCharsets.UTF_8)),
                "source bytes lost or duplicated");
            for (var function : source.functions()) {
                require(plan.locate(function.startLine()).file() == plan.locate(function.endLine()).file(),
                    "function or failure diagnostic split across files");
            }
            for (var row : source.mappedLines()) {
                var position = plan.locate(row.line());
                String[] lines = new String(plan.parts().get(position.file() - 1).utf8(),
                    StandardCharsets.UTF_8).split("\n", -1);
                require(lines[position.line() - 1].equals(logical[row.line() - 1]),
                    "address evidence now points at different source text");
            }
            rejected(() -> plan.locate(0));
            rejected(() -> plan.locate(logical.length));
        }
        require(Arrays.equals(before, source.utf8()), "partitioning modified original source");
        rejected(() -> SourcePartitionPlan.build(source, 0, () -> false));
        rejected(() -> SourcePartitionPlan.build(new SyntheticSourceFile(new byte[] { 'x' },
            List.of(), List.of()), 3, () -> false));
        rejected(() -> SourcePartitionPlan.build(new SyntheticSourceFile(before,
            List.of(new FunctionLines("a", 1, 8, 12, true, null),
                new FunctionLines("b", 2, 11, 13, true, null)), List.of()), 3, () -> false));
        rejected(() -> SourcePartitionPlan.build(new SyntheticSourceFile(before, List.of(),
            List.of(new SourceLine(logical.length, List.of(1L)))), 3, () -> false));
        int[] checks = { 0 };
        try {
            SourcePartitionPlan.build(source, 7, () -> ++checks[0] == 4);
            throw new AssertionError("mid-operation cancellation ignored");
        }
        catch (CancellationException expected) { }
        var declarations = new SyntheticSourceFile("/* globals only */\nint value;\n".getBytes(StandardCharsets.UTF_8),
            List.of(), List.of());
        require(SourcePartitionPlan.build(declarations, 1, () -> false).parts().size() == 1,
            "indivisible global preamble split");
        boundaryEvidence(source);
        System.out.println("source-partition-smoke=PASS");
    }

    private static void boundaryEvidence(SyntheticSourceFile source) {
        for (int[] pair : new int[][] {{0, 1}, {1, 0}, {-1, 1}, {1, -1}}) {
            rejected(() -> new SourcePartitionPlan.Position(pair[0], pair[1]));
        }
        byte[] bytes = "first\nsecond\nthird\n".getBytes(StandardCharsets.UTF_8);
        var complete = new FunctionLines("whole", 0x1000, 1, 3, true, null);
        var raw = new SyntheticSourceFile(bytes, List.of(complete), List.of(new SourceLine(3, List.of(0x1000L))),
            List.of(new SyntheticSourceFile.FunctionTokens("whole", 0x1000, List.of(new SourceLine(3, List.of(0x1000L))))));
        for (int limit : new int[] {2, 3, Integer.MAX_VALUE}) {
            var plan = SourcePartitionPlan.build(raw, limit, () -> false);
            require(plan.parts().size() == 1 && plan.parts().getFirst().oversized() == (limit == 2),
                "function starting at line one lost its indivisible boundary");
            require(plan.logicalLineCount() == 3 && plan.locate(3).equals(new SourcePartitionPlan.Position(1, 5)),
                "last executable line shifted incorrectly past the synthetic header");
            plan.requireSource(raw);
            plan.requireSource(new SyntheticSourceFile(bytes.clone(), List.of(complete), raw.mappedLines(), raw.functionTokens()));
            rejected(() -> plan.requireSource(null));
            rejected(() -> plan.requireSource(new SyntheticSourceFile(
                "first\nsecond\nother\n".getBytes(StandardCharsets.UTF_8), List.of(complete), List.of())));
            byte[] header = SourcePartitionPlan.syntheticHeader();
            byte[] expected = new byte[header.length + bytes.length];
            System.arraycopy(header, 0, expected, 0, header.length);
            System.arraycopy(bytes, 0, expected, header.length, bytes.length);
            require(Arrays.equals(expected, plan.parts().getFirst().utf8()), "partition altered source bytes");
            header[0] = 0;
            byte[] returned = plan.parts().getFirst().utf8();
            returned[0] = 0;
            require(Arrays.equals(expected, plan.parts().getFirst().utf8()) && SourcePartitionPlan.syntheticHeader()[0] == '/',
                "caller mutation changed partition bytes or shared header");
        }
        rejected(() -> SourcePartitionPlan.build(new SyntheticSourceFile(new byte[0], List.of(), List.of()), 1, () -> false));
        for (int[] range : new int[][] {{0, 1}, {2, 1}, {1, 4}}) {
            var invalid = new FunctionLines("invalid", 0x1000, range[0], range[1], true, null);
            rejected(() -> SourcePartitionPlan.build(new SyntheticSourceFile(bytes, List.of(invalid), List.of()), 1, () -> false));
        }
        for (int line : new int[] {0, 4}) {
            var invalid = new SourceLine(line, List.of(0x1000L));
            rejected(() -> SourcePartitionPlan.build(new SyntheticSourceFile(bytes, List.of(complete), List.of(invalid)), 1, () -> false));
            rejected(() -> SourcePartitionPlan.build(new SyntheticSourceFile(bytes, List.of(complete), List.of(),
                List.of(new SyntheticSourceFile.FunctionTokens("whole", 0x1000, List.of(invalid)))), 1, () -> false));
        }
        int[] polls = {0};
        var baseline = SourcePartitionPlan.build(source, 7, () -> { polls[0]++; return false; });
        for (int stop = 1; stop <= polls[0]; stop++) {
            int selected = stop;
            int[] seen = {0};
            try {
                SourcePartitionPlan.build(source, 7, () -> ++seen[0] == selected);
                throw new AssertionError("partitioning ignored cancellation at " + selected);
            }
            catch (CancellationException expected) { }
            var retry = SourcePartitionPlan.build(source, 7, () -> false);
            require(baseline.sourceSha256().equals(retry.sourceSha256()) && baseline.parts().size() == retry.parts().size(),
                "cancelled partitioning contaminated retry");
            for (int part = 0; part < baseline.parts().size(); part++) {
                require(Arrays.equals(baseline.parts().get(part).utf8(), retry.parts().get(part).utf8()),
                    "cancelled partitioning changed a later output part");
            }
        }
        System.out.println("source-partition-boundaries=PASS cancellation=" + polls[0]);
    }

    private static void rejected(Runnable operation) {
        try {
            operation.run();
            throw new AssertionError("invalid source partition accepted");
        }
        catch (IllegalArgumentException expected) { }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
