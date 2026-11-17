package ghidradwarfforge.types;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

import ghidradwarfforge.types.ClassScopeModel.*;
import ghidradwarfforge.types.FunctionRelations.Thunk;
import ghidradwarfforge.types.TypeGraph.*;

/** Model boundaries only: relationships never establish storage or object-layout evidence. */
public final class ScopeRelationshipBoundarySmoke {
    private static int checks;
    private static final TypeRef INTEGER = new TypeRef("int");
    private static final TypeRef OBJECT = new TypeRef("object");

    public static void check() {
        sharedTargetsAndIdentity();
        boundedDeepChain();
        classWitnesses();
        System.out.println("scope-relationship-boundaries=PASS checks=" + checks);
    }

    private static void sharedTargetsAndIdentity() {
        var first = FunctionReference.definition("same", 0);
        var second = FunctionReference.definition("same", 16);
        var external = FunctionReference.declaration("same", "library:a");
        var otherExternal = FunctionReference.declaration("same", "library:b");
        var one = new Thunk(10, first, 30, external, "saved target a");
        var two = new Thunk(20, second, 30, external, "saved target a");
        var input = new ArrayList<>(List.of(two, one));
        var graph = new FunctionRelations(input);
        input.clear();
        require(graph.thunks().equals(List.of(one, two)), "shared endpoint or stable address order lost");
        var definitions = List.of(signature("same", 0, List.of()), signature("same", 16, List.of()));
        graph.validate(definitions, List.of(declaration("library:a", List.of())));
        reject(() -> graph.validate(definitions.subList(1, 2), List.of(declaration("library:a", List.of()))),
            "absent origin");
        reject(() -> graph.validate(definitions, List.of(declaration("library:b", List.of()))),
            "same spelling cannot replace external identity");
        reject(() -> new FunctionRelations(List.of(one,
            new Thunk(20, second, 40, external, "same endpoint under another ID"))), "endpoint has two saved IDs");
        reject(() -> new FunctionRelations(List.of(one,
            new Thunk(20, second, 30, otherExternal, "same ID for different declaration"))),
            "saved ID has two external identities");
        var distinct = new FunctionRelations(List.of(one,
            new Thunk(20, second, 40, otherExternal, "separate external identity")));
        distinct.validate(definitions, List.of(declaration("library:a", List.of()), declaration("library:b", List.of())));
        require(distinct.thunks().get(1).target().equals(otherExternal), "external targets merged by spelling");
        reject(() -> new Thunk(0, first, 30, external, "evidence"), "reserved origin ID");
        reject(() -> new Thunk(10, first, 0, external, "evidence"), "reserved endpoint ID");
        reject(() -> new Thunk(10, first, 30, external, " \n"), "blank relationship evidence");
        reject(() -> new Thunk(10, first, 30, external, null), "missing relationship evidence");
        try {
            graph.thunks().clear();
            throw new AssertionError("admitted relationships are mutable");
        }
        catch (UnsupportedOperationException expected) { checks++; }
    }

    private static void boundedDeepChain() {
        var chain = new ArrayList<Thunk>();
        for (int index = 0; index < 65536; index++) {
            chain.add(new Thunk(index + 1, FunctionReference.definition("thunk", 16L * index),
                index + 2, FunctionReference.definition("thunk", 16L * (index + 1)), "saved direct target"));
        }
        var shuffled = new ArrayList<>(chain);
        Collections.shuffle(shuffled, new Random(209));
        var graph = new FunctionRelations(shuffled);
        require(graph.thunks().equals(chain), "full admitted chain changed an edge, evidence or order");
        shuffled.clear();
        require(graph.thunks().size() == 65536, "caller mutation changed admitted chain");
        var excessive = new ArrayList<>(chain);
        excessive.add(new Thunk(65537, FunctionReference.definition("thunk", 16L * 65536),
            65538, FunctionReference.definition("thunk", 16L * 65537), "one edge beyond limit"));
        reject(() -> new FunctionRelations(excessive), "excessive relationship graph");
        // Close a long cycle within the admitted edge budget, so capacity is not the refusal reason.
        var cyclic = new ArrayList<>(chain.subList(0, 65535));
        cyclic.add(new Thunk(65536, FunctionReference.definition("thunk", 16L * 65535),
            1, FunctionReference.definition("thunk", 0), "back edge to first origin"));
        reject(() -> new FunctionRelations(cyclic), "long relationship cycle");
    }

    private static void classWitnesses() {
        var scopes = new ArrayList<>(List.of(new Scope(1, 0, "Same", Kind.CLASS)));
        var binding = new Binding(1, OBJECT, BindingSource.CURRENT_AUTO_THIS, "current object witness");
        var method = new Method(2, 1, "inspect", FunctionReference.declaration("same", "library:a"));
        var bindings = new ArrayList<>(List.of(binding));
        var methods = new ArrayList<>(List.of(method));
        var model = new ClassScopeModel(scopes, bindings, methods);
        scopes.clear();
        bindings.clear();
        methods.clear();
        require(model.scopes().size() == 1 && model.bindings().equals(List.of(binding)) &&
            model.methods().equals(List.of(method)), "caller mutation changed class identity");
        var types = new TypeGraph(List.of(
            new BaseType("int", "int", 4, BaseEncoding.SIGNED),
            new AggregateType("object", "Same", 4, AggregateKind.STRUCTURE, List.of(new Member("value", INTEGER, 0))),
            new AggregateType("union", "Same", 4, AggregateKind.UNION, List.of(new Member("value", INTEGER, 0))),
            new IndirectionType("pointer", "Same *", 8, IndirectionKind.POINTER, OBJECT)));
        var ordinary = new Parameter("candidate", new TypeRef("pointer"), false, false, false);
        reject(() -> model.validate(types, List.of(), List.of(declaration("library:a", List.of(ordinary)))),
            "ordinary pointer is not an object witness");
        var scalarReceiver = new Parameter("receiver", INTEGER, true, false, true);
        reject(() -> model.validate(types, List.of(), List.of(declaration("library:a", List.of(scalarReceiver)))),
            "scalar object parameter cannot prove a class layout");
        var receiver = new Parameter("receiver", new TypeRef("pointer"), true, false, true);
        model.validate(types, List.of(), List.of(declaration("library:a", List.of(ordinary, receiver))));
        require(model.bindings().getFirst().source() == BindingSource.CURRENT_AUTO_THIS,
            "current witness became explicit saved evidence");
        reject(() -> model.validate(types, List.of(), List.of(declaration("library:b", List.of(receiver)))),
            "same-named declaration does not own this method");
        var unionBinding = new ClassScopeModel(model.scopes(), List.of(new Binding(1,
            new TypeRef("union"), BindingSource.EXPLICIT_SAVED, "saved identity")), List.of());
        reject(() -> unionBinding.validate(types, List.of(), List.of()), "union cannot stand in for a class structure");
        var saved = new ClassScopeModel(model.scopes(), List.of(new Binding(1, OBJECT,
            BindingSource.EXPLICIT_SAVED, "saved layout")), model.methods());
        saved.validate(types, List.of(), List.of(declaration("library:a", List.of(ordinary))));
        require(saved.bindings().getFirst().type().equals(OBJECT), "saved layout lost without receiver");
    }

    private static ProgramTypeModel.FunctionSignature signature(String name, long address, List<Parameter> parameters) {
        return new ProgramTypeModel.FunctionSignature(name, address, INTEGER, parameters, List.of(),
            false, false, "default", "USER_DEFINED");
    }

    private static ProgramTypeModel.FunctionDeclaration declaration(String key, List<Parameter> parameters) {
        return new ProgramTypeModel.FunctionDeclaration(key, "same", INTEGER, parameters,
            false, false, "default", "USER_DEFINED");
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }

    private static void reject(Runnable operation, String message) {
        checks++;
        try { operation.run(); }
        catch (IllegalArgumentException expected) { return; }
        throw new AssertionError("invalid relationship accepted: " + message);
    }
}
