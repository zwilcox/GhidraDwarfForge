package ghidradwarfforge.source;

import java.nio.charset.StandardCharsets;
import java.nio.ByteOrder;
import ghidradwarfforge.coverage.SourceCoverage;
import ghidradwarfforge.coverage.SourceCoverageIndex;
import ghidradwarfforge.dwarf.Dwarf5LineTable;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import java.util.Arrays;
import java.util.List;

import ghidradwarfforge.source.SyntheticSourceFile.FunctionText;
import ghidradwarfforge.source.SyntheticSourceFile.RelativeLine;

/** Native-free determinism and formatting checks for synthetic source. */
public final class SyntheticSourceSmoke {
    private SyntheticSourceSmoke() {
    }

    public static void main(String[] args) {
        List<FunctionText> functions = List.of(
            new FunctionText("later", 0x2000, "int later(void)\r\n{\r\n  return 2;\r\n}\r\n", null),
            new FunctionText("failed*/name", 0x1800, null, "controlled\nfailure */ test"),
            new FunctionText("first", 0x1000, "int first(void) { return 1; }   \n\n", null,
                List.of(new RelativeLine(1, List.of(0x1004L, 0x1000L, 0x1000L)))));
        SyntheticSourceFile first = SyntheticSourceFile.build("fixture*/name",
            "x86:LE:64", functions);
        SyntheticSourceFile second = SyntheticSourceFile.build("fixture*/name",
            "x86:LE:64", functions);
        if (!Arrays.equals(first.utf8(), second.utf8())) {
            throw new AssertionError("synthetic source is not deterministic");
        }
        String text = new String(first.utf8(), StandardCharsets.UTF_8);
        if (text.indexOf("int first") > text.indexOf("failed* /name") ||
                text.indexOf("failed* /name") > text.indexOf("int later")) {
            throw new AssertionError("functions are not ordered by address");
        }
        if (text.contains("\r") || text.contains("*/name") ||
                !text.contains("not recovered original source")) {
            throw new AssertionError("source normalization/header check failed");
        }
        if (first.functions().size() != 3 || first.functions().get(0).startLine() != 8 ||
                !first.functions().get(0).decompiled() ||
                first.functions().get(1).decompiled()) {
            throw new AssertionError("function line metadata is incorrect");
        }
        if (first.mappedLines().size() != 2 || first.mappedLines().get(0).line() != 8 ||
                !first.mappedLines().get(0).addresses().equals(List.of(0x1000L, 0x1004L)) ||
                first.mappedLines().get(1).line() != 12 ||
                !first.mappedLines().get(1).addresses().equals(List.of(0x2000L))) {
            throw new AssertionError("address-to-line normalization is incorrect");
        }
        if (first.functionTokens().size() != 3 ||
                first.functionTokens().get(0).lines().size() != 1 ||
                first.functionTokens().get(0).lines().get(0).line() != 8 ||
                !first.functionTokens().get(0).lines().get(0).addresses().equals(List.of(0x1000L, 0x1004L)) ||
                !first.functionTokens().get(1).lines().isEmpty() ||
                !first.functionTokens().get(2).lines().isEmpty()) {
            throw new AssertionError("token provenance includes declaration-only or failed rows");
        }
        var legacy = new SyntheticSourceFile(first.utf8(), first.functions(), first.mappedLines());
        if (!legacy.functionTokens().isEmpty()) {
            throw new AssertionError("manual source acquired invented token evidence");
        }
        var symbols = first.functions().stream().map(function ->
            new FunctionSymbol(function.name(), function.address(), 8)).toList();
        var emission = Dwarf5LineTable.buildWithPlan("fixture.dbg.c", "/fixture", 8,
            ByteOrder.LITTLE_ENDIAN, symbols, first.mappedLines());
        var coverage = new SourceCoverageIndex(emission, () -> false);
        if (!coverage.measure(symbols.get(0), List.of(0x1000L, 0x1004L),
                first.functionTokens().get(0).lines(), () -> false).equals(new SourceCoverage(2, 2, 2)) ||
                !coverage.measure(symbols.get(1), List.of(0x1800L, 0x1804L),
                    first.functionTokens().get(1).lines(), () -> false).equals(new SourceCoverage(2, 0, 0)) ||
                !coverage.measure(symbols.get(2), List.of(0x2000L, 0x2004L),
                    first.functionTokens().get(2).lines(), () -> false).equals(new SourceCoverage(2, 0, 2))) {
            throw new AssertionError("actual source evidence does not distinguish failure, tokens and declarations");
        }
        System.out.println("synthetic-source-smoke=PASS");
    }
}
