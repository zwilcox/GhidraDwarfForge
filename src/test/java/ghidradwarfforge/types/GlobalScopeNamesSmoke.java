package ghidradwarfforge.types;

import java.util.ArrayList;
import java.util.List;

public final class GlobalScopeNamesSmoke {
    private static int checks;
    private static final TypeGraph.TypeRef INTEGER = new TypeGraph.TypeRef("int");
    private static final TypeGraph GRAPH = new TypeGraph(List.of(
        new TypeGraph.BaseType("int", "int", 4, TypeGraph.BaseEncoding.SIGNED)));

    private static ProgramTypeModel.GlobalVariable variable(String name, long address, String... path) {
        return new ProgramTypeModel.GlobalVariable(name, address, 4, INTEGER, false, "USER_DEFINED", List.of(path));
    }

    public static void main(String[] args) {
        var left = variable("item", 0x1000, "left");
        var right = variable("item", 0x2000, "right");
        var root = variable("item", 0x3000);
        var unique = variable("unique", 0x4000, "left", "nested");
        var values = new ArrayList<>(List.of(left, right, root, unique));
        var plan = GlobalScopeNames.build(values, GRAPH, List.of());
        require(plan.qualified().equals(java.util.Set.of(left, right, unique)), "distinct scopes retain full names");
        require(plan.shortAliases().equals(java.util.Set.of(unique)), "ambiguous leaves cannot shadow the root object");
        require(GlobalScopeNames.qualifiedName(unique).equals("left::nested::unique"), "nested saved path");
        require(!plan.qualified().contains(root), "ordinary root variable remains unchanged");
        require(plan.diagnostics().isEmpty(), "ordinary same leaf names are not errors");
        var external = new ProgramTypeModel.GlobalVariable("missing", 0, 4, INTEGER, true, "USER_DEFINED", List.of("left"));
        require(GlobalScopeNames.build(List.of(external), GRAPH, List.of()).qualified().contains(external), "addressless declaration has qualified identity");
        values.add(variable("left::item", 0x5000));
        var conflict = GlobalScopeNames.build(values, GRAPH, List.of());
        require(!conflict.qualified().contains(left) && conflict.qualified().contains(right), "literal full-name collision retains original namespace");
        require(conflict.diagnostics().size() == 1 && conflict.diagnostics().getFirst().contains("left::item"), "collision diagnosed");
        conflict = GlobalScopeNames.build(List.of(left, right), GRAPH, List.of("left::item"));
        require(!conflict.qualified().contains(left) && conflict.qualified().contains(right), "function/alias collision cannot be shadowed");
        conflict = GlobalScopeNames.build(List.of(unique), GRAPH, List.of("unique"));
        require(conflict.qualified().contains(unique) && conflict.shortAliases().isEmpty(), "short function name preserved");
        var graph = new TypeGraph(List.of(GRAPH.nodes().getFirst(),
            new TypeGraph.TypedefType("alias", "unique", 4, INTEGER)));
        require(GlobalScopeNames.build(List.of(unique), graph, List.of()).shortAliases().isEmpty(), "typedef lookup preserved");
        graph = new TypeGraph(List.of(GRAPH.nodes().getFirst(),
            new TypeGraph.EnumType("enum", "Mode", 4, true, List.of(new TypeGraph.Enumerator("unique", 1)))));
        require(GlobalScopeNames.build(List.of(unique), graph, List.of()).shortAliases().isEmpty(), "enumerator value preserved");
        graph = new TypeGraph(List.of(GRAPH.nodes().getFirst(),
            new TypeGraph.TypedefType("qualified-alias", "left::item", 4, INTEGER)));
        require(GlobalScopeNames.build(List.of(left), graph, List.of()).qualified().isEmpty(), "qualified typedef lookup preserved");
        graph = new TypeGraph(List.of(GRAPH.nodes().getFirst(),
            new TypeGraph.EnumType("qualified-enum", "Mode", 4, true, List.of(new TypeGraph.Enumerator("left::item", 1)))));
        require(GlobalScopeNames.build(List.of(left), graph, List.of()).qualified().isEmpty(), "qualified enumerator lookup preserved");
        conflict = GlobalScopeNames.build(List.of(left, variable("item", 0x6000, "left")), GRAPH, List.of());
        require(conflict.qualified().isEmpty() && conflict.diagnostics().size() == 2, "duplicate full scopes not guessed");
        values.clear();
        require(plan.qualified().size() == 3, "immutable plan independent of caller list");
        require(GlobalScopeNames.build(List.of(), GRAPH, List.of()).qualified().isEmpty(), "empty inventory");
        System.out.println("global-scope-names=PASS checks=" + checks);
    }

    private static void require(boolean value, String message) {
        checks++;
        if (!value) throw new AssertionError(message);
    }
}
