package ghidradwarfforge.source;

import java.nio.charset.StandardCharsets;
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
        System.out.println("synthetic-source-smoke=PASS");
    }
}
