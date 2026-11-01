package ghidradwarfforge.types;

import java.util.List;

import ghidradwarfforge.locations.VariableStorageModel;
import ghidradwarfforge.types.ClassScopeModel.FunctionReference;
import ghidradwarfforge.types.FunctionRelations.Thunk;

/** Relationship validation is independent of names, source text and variable storage. */
public final class FunctionRelationsSmoke {
    private static int checks;

    public static ProgramTypeModel withRelations(ProgramTypeModel model) {
        var first = model.functions().get(0);
        var second = model.functions().get(1);
        var relations = new FunctionRelations(List.of(new Thunk(100,
            FunctionReference.definition(first.name(), first.address()), 101,
            FunctionReference.definition(second.name(), second.address()), "call-policy retention fixture")));
        return new ProgramTypeModel(model.types(), model.functions(), model.globals(), model.variableStorage(),
            model.functionStatics(), model.functionDeclarations(), model.lexicalScopes(), model.classScopes(), relations);
    }

    public static void main(String[] args) {
        var first = FunctionReference.definition("gateway", 0x1000);
        var second = FunctionReference.definition("bridge", 0x2000);
        var target = FunctionReference.definition("implementation", 0x3000);
        var external = FunctionReference.declaration("external", "external:4");
        var one = new Thunk(1, first, 2, second, "saved direct target");
        var two = new Thunk(2, second, 3, target, "saved direct target");
        var graph = new FunctionRelations(List.of(two, one));
        require(graph.thunks().equals(List.of(one, two)), "stable chain order");
        reject(() -> new Thunk(1, first, 1, first, "self"));
        reject(() -> new Thunk(1, external, 3, target, "addressless origin"));
        reject(() -> new Thunk(1, first, 3, FunctionReference.definition("other", 0x1000), "same entry"));
        reject(() -> new FunctionRelations(List.of(one, one)));
        reject(() -> new FunctionRelations(List.of(one, new Thunk(2, second, 1, first, "cycle"))));
        reject(() -> new FunctionRelations(List.of(one, new Thunk(2, target, 4, external, "conflicting ID"))));
        reject(() -> new FunctionRelations(List.of(one, new Thunk(4, second, 3, target, "conflicting owner ID"))));
        var integer = new TypeGraph.TypeRef("int");
        var types = new TypeGraph(List.of(new TypeGraph.BaseType("int", "int", 4, TypeGraph.BaseEncoding.SIGNED)));
        var functions = List.of(first, second, target).stream().map(f -> new ProgramTypeModel.FunctionSignature(
            f.name(), f.address(), integer, List.of(), List.of(), false, false, "default", "USER_DEFINED")).toList();
        var declarations = List.of(new ProgramTypeModel.FunctionDeclaration("external:4", "external", integer,
            List.of(), false, false, "default", "USER_DEFINED"));
        var model = new ProgramTypeModel(types, functions, List.of(), new VariableStorageModel(List.of()), List.of(),
            declarations, List.of(), ClassScopeModel.empty(), graph);
        require(model.functionRelations().equals(graph), "model keeps exact identities");
        require(model.variableStorage().variables().isEmpty(), "relationship does not invent locations");
        reject(() -> new ProgramTypeModel(types, functions.subList(0, 2), List.of(), new VariableStorageModel(List.of()), List.of(),
            declarations, List.of(), ClassScopeModel.empty(), graph));
        new FunctionRelations(List.of(new Thunk(1, first, 4, external, "known external identity"))).validate(functions, declarations);
        checks++;
        reject(() -> graph.thunks().add(one));
        System.out.println("function-relations=PASS checks=" + checks);
    }

    private static void reject(Runnable action) {
        try { action.run(); throw new AssertionError("invalid relationship accepted"); }
        catch (IllegalArgumentException | UnsupportedOperationException expected) { checks++; }
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
