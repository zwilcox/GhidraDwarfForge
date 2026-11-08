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
        System.out.println("source-partition-smoke=PASS");
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
