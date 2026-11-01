package ghidradwarfforge.types;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

import ghidradwarfforge.locations.VariableStorageModel;
import ghidradwarfforge.types.ClassScopeModel.*;
import ghidradwarfforge.types.TypeGraph.*;

/** Identity, type conflicts and retained ownership; this is not an emission test. */
public final class ClassScopeModelSmoke {
    private static int checks;
    private static final TypeRef INTEGER = new TypeRef("int");
    private static final TypeRef LEFT = new TypeRef("left-type");
    private static final TypeRef RIGHT = new TypeRef("right-type");
    private static final List<Scope> SCOPES = List.of(
        new Scope(1, 0, "left", Kind.NAMESPACE), new Scope(2, 0, "right", Kind.NAMESPACE),
        new Scope(3, 1, "Same", Kind.CLASS), new Scope(4, 2, "Same", Kind.CLASS),
        new Scope(5, 3, "Nested", Kind.CLASS));
    private static final List<Method> METHODS = List.of(
        new Method(101, 3, "inspect", FunctionReference.definition("left::Same::inspect", 0x1000)),
        new Method(102, 4, "inspect", FunctionReference.definition("right::Same::inspect", 0x2000)),
        new Method(103, 3, "external", FunctionReference.declaration("left::Same::external", "external:103")));
    private static final TypeGraph TYPES = new TypeGraph(List.of(
        new BaseType("int", "int", 4, BaseEncoding.SIGNED),
        new AggregateType(LEFT.key(), "Same", 4, AggregateKind.STRUCTURE, List.of(new Member("a", INTEGER, 0))),
        new AggregateType(RIGHT.key(), "Same", 8, AggregateKind.STRUCTURE, List.of(new Member("b", INTEGER, 4))),
        new IndirectionType("left-pointer", "Same *", 8, IndirectionKind.POINTER, new TypeRef("left-alias")),
        new IndirectionType("right-pointer", "Same *", 8, IndirectionKind.LVALUE_REFERENCE, RIGHT),
        new QualifiedType("qualified-pointer", "Same * const", 8, List.of(Qualifier.CONST), new TypeRef("left-pointer")),
        new QualifiedType("left-const", "const Same", 4, List.of(Qualifier.CONST), LEFT),
        new TypedefType("left-alias", "object_alias", 4, new TypeRef("left-const")),
        new TypedefType("cycle", "cycle", 8, new TypeRef("cycle")),
        new IndirectionType("cyclic-pointer", "cycle *", 8, IndirectionKind.POINTER, new TypeRef("cycle"))));

    private static ProgramTypeModel.FunctionSignature signature(String name, long address, String pointer) {
        return new ProgramTypeModel.FunctionSignature(name, address, INTEGER,
            pointer == null ? List.of() : List.of(new Parameter("receiver", new TypeRef(pointer), true, false, true)),
            List.of(), false, false, "default", "USER_DEFINED");
    }

    private static List<ProgramTypeModel.FunctionSignature> functions() {
        return List.of(signature("left::Same::inspect", 0x1000, "qualified-pointer"),
            signature("right::Same::inspect", 0x2000, "right-pointer"));
    }

    private static List<ProgramTypeModel.FunctionDeclaration> declarations() {
        return List.of(new ProgramTypeModel.FunctionDeclaration("external:103", "left::Same::external", INTEGER,
            List.of(new Parameter("receiver", new TypeRef("left-pointer"), true, false, true)),
            false, false, "default", "USER_DEFINED"));
    }

    private static Binding binding(long owner, TypeRef type, BindingSource source) {
        return new Binding(owner, type, source, "fixture identity evidence");
    }

    private static ProgramTypeModel model(ClassScopeModel scopes) {
        return new ProgramTypeModel(TYPES, functions(), List.of(), new VariableStorageModel(List.of()),
            List.of(), declarations(), List.of(), scopes);
    }

    /** Give call-policy fixtures nonempty ownership, so dropped metadata is observable. */
    public static ProgramTypeModel withOwnership(ProgramTypeModel model) {
        var methods = new ArrayList<Method>();
        long id = 100;
        for (var function : model.functions()) methods.add(new Method(id++, 1, function.name(),
            FunctionReference.definition(function.name(), function.address())));
        for (var declaration : model.functionDeclarations()) methods.add(new Method(id++, 1, declaration.name(),
            FunctionReference.declaration(declaration.name(), declaration.key())));
        var scopes = new ClassScopeModel(List.of(new Scope(1, 0, "fixture_owner", Kind.CLASS)), List.of(), methods);
        return new ProgramTypeModel(model.types(), model.functions(), model.globals(), model.variableStorage(),
            model.functionStatics(), model.functionDeclarations(), model.lexicalScopes(), scopes);
    }

    public static void main(String[] args) {
        var bindings = List.of(binding(3, LEFT, BindingSource.EXPLICIT_SAVED),
            binding(4, RIGHT, BindingSource.CURRENT_AUTO_THIS));
        var scopes = new ClassScopeModel(SCOPES, bindings, METHODS);
        var model = model(scopes);
        check(model.classScopes() == scopes, "class identity retained");
        check(scopes.scopes().indexOf(SCOPES.get(0)) < scopes.scopes().indexOf(SCOPES.get(2)), "namespace before class");
        check(scopes.scopes().indexOf(SCOPES.get(2)) < scopes.scopes().indexOf(SCOPES.get(4)), "class before nested class");
        check(scopes.bindings().stream().map(b -> b.type().key()).distinct().count() == 2, "same names retain distinct canonical types");
        for (int seed = 0; seed < 16; seed++) {
            var shuffledScopes = new ArrayList<>(SCOPES);
            var shuffledMethods = new ArrayList<>(METHODS);
            var shuffledBindings = new ArrayList<>(bindings);
            Collections.shuffle(shuffledScopes, new Random(seed));
            Collections.shuffle(shuffledMethods, new Random(seed + 1));
            Collections.shuffle(shuffledBindings, new Random(seed + 2));
            check(new ClassScopeModel(shuffledScopes, shuffledBindings, shuffledMethods).equals(scopes), "stable graph ordering");
        }
        model(new ClassScopeModel(SCOPES, List.of(), METHODS));
        checks++; // Ownership exists independently of layout and object-parameter evidence.
        rejects(() -> new Scope(0, 0, "global", Kind.NAMESPACE), "reserved global ID");
        rejects(() -> new Scope(1, 1, "cycle", Kind.CLASS), "self parent");
        rejects(() -> new Scope(1, 0, "bad\0name", Kind.CLASS), "NUL name");
        rejects(() -> new ClassScopeModel(List.of(SCOPES.getFirst(), SCOPES.getFirst()), List.of(), List.of()), "duplicate scope");
        rejects(() -> new ClassScopeModel(List.of(new Scope(1, 2, "a", Kind.CLASS)), List.of(), List.of()), "missing parent");
        rejects(() -> new ClassScopeModel(List.of(new Scope(1, 2, "a", Kind.CLASS), new Scope(2, 1, "b", Kind.CLASS)),
            List.of(), List.of()), "cycle");
        rejects(() -> new ClassScopeModel(SCOPES, List.of(binding(1, LEFT, BindingSource.EXPLICIT_SAVED)), List.of()), "namespace is not class");
        rejects(() -> new ClassScopeModel(SCOPES, List.of(binding(99, LEFT, BindingSource.EXPLICIT_SAVED)), List.of()), "missing class");
        rejects(() -> new ClassScopeModel(SCOPES, List.of(bindings.getFirst(), bindings.getFirst()), METHODS), "duplicate binding");
        rejects(() -> new ClassScopeModel(SCOPES, List.of(bindings.getFirst(), binding(4, LEFT, BindingSource.EXPLICIT_SAVED)), METHODS), "one type cannot acquire two owners");
        rejects(() -> new ClassScopeModel(SCOPES, List.of(), List.of(METHODS.getFirst(), METHODS.getFirst())), "duplicate method");
        rejects(() -> new ClassScopeModel(SCOPES, List.of(), List.of(new Method(3, 3, "inspect", METHODS.getFirst().function()))), "scope and method IDs collide");
        rejects(() -> new ClassScopeModel(SCOPES, List.of(), List.of(METHODS.getFirst(),
            new Method(200, 4, "inspect", METHODS.getFirst().function()))), "function cannot have two class owners");
        rejects(() -> model(new ClassScopeModel(SCOPES, List.of(binding(3, RIGHT, BindingSource.EXPLICIT_SAVED)), METHODS)), "object disagrees with explicit layout");
        rejects(() -> model(new ClassScopeModel(SCOPES, List.of(binding(3, INTEGER, BindingSource.EXPLICIT_SAVED)), METHODS)), "class is not scalar");
        rejects(() -> model(new ClassScopeModel(SCOPES, List.of(binding(3, new TypeRef("missing"), BindingSource.EXPLICIT_SAVED)), METHODS)), "missing canonical type");
        rejects(() -> model(new ClassScopeModel(SCOPES, List.of(binding(3, new TypeRef("left-alias"), BindingSource.EXPLICIT_SAVED)), METHODS)), "binding must be canonical aggregate");
        var inferred = new ClassScopeModel(SCOPES, List.of(binding(3, LEFT, BindingSource.CURRENT_AUTO_THIS)), List.of());
        rejects(() -> model(inferred), "inference without object witness");
        var staticMethod = new ClassScopeModel(SCOPES, List.of(binding(3, LEFT, BindingSource.EXPLICIT_SAVED)), List.of(METHODS.getFirst()));
        staticMethod.validate(TYPES, List.of(signature("left::Same::inspect", 0x1000, null)), List.of());
        checks++;
        var inferredStatic = new ClassScopeModel(SCOPES, List.of(binding(3, LEFT, BindingSource.CURRENT_AUTO_THIS)), List.of(METHODS.getFirst()));
        rejects(() -> inferredStatic.validate(TYPES, List.of(signature("left::Same::inspect", 0x1000, null)), List.of()), "static method cannot witness object layout");
        rejects(() -> staticMethod.validate(TYPES, List.of(signature("left::Same::inspect", 0x1000, "cyclic-pointer")), List.of()), "cyclic object alias");
        rejects(() -> scopes.validate(TYPES, List.of(), declarations()), "missing definition");
        rejects(() -> scopes.validate(TYPES, List.of(functions().getFirst(), functions().getFirst()), declarations()), "ambiguous definition");
        rejects(() -> scopes.validate(TYPES, functions(), List.of()), "missing external declaration");
        rejects(() -> scopes.validate(TYPES, functions(), List.of(declarations().getFirst(), declarations().getFirst())), "ambiguous declaration");
        rejects(() -> FunctionReference.definition("method", -1), "negative image address");
        rejects(() -> new FunctionReference("method", 0, "external"), "external cannot acquire image address");
        check(FunctionReference.definition("method", 0).address() == 0, "zero image address remains valid");
        var deep = new ArrayList<Scope>();
        for (int index = 1; index <= 4096; index++) deep.add(new Scope(index, index - 1, "nested", Kind.CLASS));
        check(new ClassScopeModel(deep, List.of(), List.of()).scopes().size() == 4096, "deep graph avoids recursive traversal");
        check(new ProgramTypeModel(TYPES, functions(), List.of()).classScopes().equals(ClassScopeModel.empty()), "compatible constructor has no invented ownership");
        System.out.println("class-scope-model=PASS checks=" + checks);
    }

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }

    private static void rejects(Runnable operation, String message) {
        checks++;
        try {
            operation.run();
        }
        catch (IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError(message);
    }
}
