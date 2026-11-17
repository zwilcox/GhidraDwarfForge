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
            FormatterWitnessAdmissionSmoke.run(root);
            Path selection = root.resolve("selection.json");
            selectionBoundaries(selection);
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

    private static void selectionBoundaries(Path file) throws Exception {
        var mutable = new java.util.LinkedHashMap<String, String>();
        var rows = new java.util.ArrayList<String>();
        for (int i = 127; i >= 0; i--) {
            String key = "canonical" + i;
            String mode = i % 2 == 0 ? "flags" : "structure";
            mutable.put(key, mode);
            rows.add("{\"key\":\"" + key + "\",\"mode\":\"" + mode + "\"}");
        }
        FormatterSelection exact;
        try { exact = new FormatterSelection(mutable); }
        catch (IllegalArgumentException refused) { throw new AssertionError("exact 128-selection limit refused", refused); }
        require(exact.modes().equals(mutable), "formatter selection lost canonical choices");
        var expectedOrder = mutable.keySet().stream().sorted().toList();
        require(List.copyOf(exact.modes().keySet()).equals(expectedOrder), "formatter selection order is not canonical");
        mutable.clear();
        require(exact.modes().size() == 128, "formatter selection retained mutable map");
        try { exact.modes().clear(); throw new AssertionError("formatter choices are mutable"); }
        catch (UnsupportedOperationException expected) { }
        mutable.putAll(exact.modes());
        mutable.put("extra", "flags");
        try { new FormatterSelection(mutable); throw new AssertionError("129 formatter selections accepted"); }
        catch (IllegalArgumentException expected) { }
        for (String blank : List.of("", " ", "\t\n")) {
            try { new FormatterSelection(Map.of(blank, "flags")); throw new AssertionError("blank canonical key accepted"); }
            catch (IllegalArgumentException expected) { }
        }
        String prefix = "{\"schema\":1,\"types\":[";
        String valid = prefix + String.join(",", rows) + "]}";
        Files.writeString(file, valid);
        require(FormatterSelection.read(file, () -> false).equals(exact), "128 formatter choices changed during parsing");
        for (String bad : List.of(prefix + String.join(",", rows) + "," + rows.getFirst() + "]}",
                prefix + rows.getFirst() + "," + rows.getFirst().replace("structure", "flags") + "]}",
                prefix + String.join(",", rows) + ",{\"key\":\"extra\",\"mode\":\"flags\"}]}")) {
            Files.writeString(file, bad);
            byte[] before = Files.readAllBytes(file);
            try { FormatterSelection.read(file, () -> false); throw new AssertionError("duplicate or oversized formatter selection accepted"); }
            catch (java.io.IOException expected) { }
            require(java.util.Arrays.equals(before, Files.readAllBytes(file)), "formatter rejection changed selection file");
        }
        System.out.println("formatter-selection-boundaries=PASS exact=128 overflow=129 duplicate-modes=refused");
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
