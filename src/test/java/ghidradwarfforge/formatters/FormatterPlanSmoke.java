package ghidradwarfforge.formatters;

import ghidradwarfforge.output.FormatterSelection;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.TypeGraph;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;

/** Selection grammar, canonical binding, ambiguity retention and deterministic data encoding. */
public final class FormatterPlanSmoke {
    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("forge-formatter-plan-");
        try {
            Path selection = root.resolve("selection.json");
            String good = "{\"schema\":1,\"types\":[{\"key\":\"flags\",\"mode\":\"flags\"}]}";
            Files.writeString(selection, good);
            var choices = FormatterSelection.read(selection, () -> false);
            var enumeration = new TypeGraph.EnumType("flags", "Flags", 8, true,
                List.of(new TypeGraph.Enumerator("NONE", 0), new TypeGraph.Enumerator("HIGH", Long.MIN_VALUE),
                    new TypeGraph.Enumerator("quote\"\\\nλ", 1)));
            var peer = new TypeGraph.EnumType("another", "Flags", 8, true, enumeration.values());
            var model = new ProgramTypeModel(new TypeGraph(List.of(enumeration, peer)), List.of(), List.of());
            var plan = FormatterPlan.prepare(model, choices, () -> false);
            require(plan.aliases().size() == 2 && plan.rules().get(0).peers().size() == 1, "lost ambiguous canonical candidate");
            require(plan.rules().get(0).flags().stream().anyMatch(flag -> flag.bits().equals("8000000000000000")), "lost unsigned high bit");
            Path original = Files.writeString(root.resolve("original"), "original bytes");
            Path sidecar = Files.writeString(root.resolve("sidecar"), "sidecar bytes");
            String first = plan.render(original, sidecar, sidecar, () -> false);
            require(first.equals(plan.render(original, sidecar, sidecar, () -> false)), "nondeterministic companion");
            require(!first.contains("quote\"\\\nλ"), "analyst text embedded in executable syntax");
            for (String invalid : List.of(good.replace("\"schema\":1", "\"schema\":2"),
                    good.replace("\"schema\":1", "\"schema\":1,\"schema\":1"),
                    good.replace("\"mode\":\"flags\"", "\"mode\":\"infer\""),
                    good.replace("\"key\":", "\"unknown\":"),
                    good + " {}", "{\"schema\":1,\"types\":[]}",
                    good.replace("flags\",\"mode", "flags\\q\",\"mode"))) {
                Files.writeString(selection, invalid);
                try { FormatterSelection.read(selection, () -> false); throw new AssertionError("invalid selection accepted: " + invalid); }
                catch (java.io.IOException expected) { }
            }
            try { FormatterPlan.prepare(model, new FormatterSelection(Map.of("missing", "flags")), () -> false); throw new AssertionError("missing key accepted"); }
            catch (IllegalArgumentException expected) { }
            try { FormatterPlan.prepare(model, new FormatterSelection(Map.of("flags", "structure")), () -> false); throw new AssertionError("wrong formatter kind accepted"); }
            catch (IllegalArgumentException expected) { }
            try { plan.render(original, sidecar, sidecar, () -> true); throw new AssertionError("render ignored cancellation"); }
            catch (CancellationException expected) { }
            try { FormatterPlan.prepare(model, choices, () -> true); throw new AssertionError("planning ignored cancellation"); }
            catch (CancellationException expected) { }
            System.out.println("formatter-plan-smoke=PASS");
        }
        finally {
            try (var files = Files.walk(root)) {
                for (Path path : files.sorted(java.util.Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
