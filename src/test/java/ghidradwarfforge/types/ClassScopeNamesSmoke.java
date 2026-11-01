package ghidradwarfforge.types;

import java.util.List;

import ghidradwarfforge.types.ClassScopeModel.*;
import ghidradwarfforge.types.TypeGraph.*;

/** Preserve curated names while exposing only unambiguous saved-scope aliases. */
public final class ClassScopeNamesSmoke {
    private static int checks;

    public static void main(String[] args) {
        var a = new TypeRef("a");
        var b = new TypeRef("b");
        var graph = new TypeGraph(List.of(new AggregateType("a", "LayoutA", 4, AggregateKind.STRUCTURE, List.of()),
            new AggregateType("b", "LayoutB", 8, AggregateKind.STRUCTURE, List.of())));
        var scopes = List.of(new Scope(1, 0, "alpha", Kind.NAMESPACE), new Scope(2, 1, "Counter", Kind.CLASS),
            new Scope(3, 0, "beta", Kind.NAMESPACE), new Scope(4, 3, "Counter", Kind.CLASS));
        var bindings = List.of(new Binding(2, a, BindingSource.EXPLICIT_SAVED, "saved A"),
            new Binding(4, b, BindingSource.EXPLICIT_SAVED, "saved B"));
        var model = new ClassScopeModel(scopes, bindings, List.of());
        var plan = ClassScopeNames.build(graph, model);
        require(plan.names().get(2L).equals("LayoutA") && plan.names().get(4L).equals("LayoutB"), "canonical names retained");
        require(plan.aliases().equals(List.of(new ClassScopeNames.Alias(2, "alpha::Counter"),
            new ClassScopeNames.Alias(4, "beta::Counter"))), "ambiguous leaf omitted, qualified identities retained");
        require(plan.diagnostics().size() == 2, "both ambiguous owners diagnosed");
        var reversed = new ClassScopeModel(scopes.reversed(), bindings.reversed(), List.of());
        require(plan.equals(ClassScopeNames.build(graph, reversed)), "order independent");
        var one = new ClassScopeModel(scopes.subList(0, 2), bindings.subList(0, 1), List.of());
        plan = ClassScopeNames.build(graph, one);
        require(plan.aliases().equals(List.of(new ClassScopeNames.Alias(2, "Counter"),
            new ClassScopeNames.Alias(2, "alpha::Counter"))) && plan.diagnostics().isEmpty(), "unique leaf and qualified aliases");
        var occupied = new TypeGraph(List.of(graph.nodes().getFirst(),
            new AggregateType("foreign", "Counter", 8, AggregateKind.STRUCTURE, List.of())));
        plan = ClassScopeNames.build(occupied, one);
        require(plan.aliases().equals(List.of(new ClassScopeNames.Alias(2, "alpha::Counter"))) &&
            plan.diagnostics().size() == 1, "alias cannot shadow unrelated curated type");
        occupied = new TypeGraph(List.of(graph.nodes().getFirst(),
            new AggregateType("foreign", "alpha::Counter", 8, AggregateKind.STRUCTURE, List.of())));
        plan = ClassScopeNames.build(occupied, one);
        require(plan.aliases().equals(List.of(new ClassScopeNames.Alias(2, "Counter"))) &&
            plan.diagnostics().size() == 1, "qualified spelling also cannot shadow a curated type");
        var unbound = new ClassScopeModel(scopes.subList(0, 2), List.of(), List.of());
        plan = ClassScopeNames.build(occupied, unbound);
        require(plan.names().get(2L).equals("__ghidra_class_scope_2") && plan.aliases().isEmpty() &&
            plan.diagnostics().size() == 2, "unbound scope uses explicit synthetic identity on collision");
        occupied = new TypeGraph(List.of(new AggregateType("foreign", "alpha::Counter", 8, AggregateKind.STRUCTURE, List.of()),
            new AggregateType("unbound-class:2", "__ghidra_class_scope_2", 4, AggregateKind.STRUCTURE, List.of())));
        plan = ClassScopeNames.build(occupied, unbound);
        require(plan.names().get(2L).equals("__ghidra_class_scope_2_"), "synthetic name cannot shadow existing spelling");
        var same = new TypeGraph(List.of(new AggregateType("a", "Counter", 4, AggregateKind.STRUCTURE, List.of()),
            new AggregateType("b", "Counter", 8, AggregateKind.STRUCTURE, List.of())));
        plan = ClassScopeNames.build(same, model);
        require(plan.names().get(2L).equals("Counter") && plan.names().get(4L).equals("Counter"), "same-name canonical types not renamed");
        require(plan.aliases().equals(List.of(new ClassScopeNames.Alias(2, "alpha::Counter"),
            new ClassScopeNames.Alias(4, "beta::Counter"))), "same-name layouts have distinct qualified aliases");
        require(ClassScopeNames.build(graph, ClassScopeModel.empty()).names().isEmpty(), "empty model stays empty");
        System.out.println("class-scope-names=PASS checks=" + checks);
    }

    private static void require(boolean value, String message) {
        checks++;
        if (!value) throw new AssertionError(message);
    }
}
