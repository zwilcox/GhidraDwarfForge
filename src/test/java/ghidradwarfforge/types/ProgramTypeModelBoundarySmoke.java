package ghidradwarfforge.types;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import ghidradwarfforge.locations.VariableStorageModel;
import ghidradwarfforge.locations.VariableStorageModel.*;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange;
import ghidradwarfforge.types.ProgramTypeModel.*;
import ghidradwarfforge.types.TypeGraph.*;

/** Declaration identity, visibility and storage proofs at the producer boundary. */
public final class ProgramTypeModelBoundarySmoke {
    private static final TypeRef INT = new TypeRef("int");
    private static final TypeRef MISSING = new TypeRef("missing");
    private static final long ENTRY = 0x1000;
    private static int checks;

    private ProgramTypeModelBoundarySmoke() { }

    public static void main(String[] args) {
        run();
    }

    public static void run() {
        checks = 0;
        try {
            ProgramDeclarationBoundarySmoke.run();
            danglingReferences();
            objectParameters();
            storageAgreement();
            lexicalOwnership();
            staticNames();
            callRestrictions();
        }
        catch (IllegalArgumentException unexpected) {
            throw new AssertionError("a valid declaration/storage fixture was rejected", unexpected);
        }
        System.out.println("program-type-model-boundary-smoke=PASS checks=" + checks);
    }

    private static TypeGraph graph() {
        return new TypeGraph(List.of(new BaseType("int", "int", 4, BaseEncoding.SIGNED)));
    }

    private static FunctionSignature function(String name, long entry, TypeRef result,
            List<Parameter> parameters, List<LocalVariable> locals) {
        return new FunctionSignature(name, entry, result, parameters, locals,
            false, false, "default", "USER_DEFINED");
    }

    private static FunctionSignature function(List<Parameter> parameters, List<LocalVariable> locals) {
        return function("function", ENTRY, INT, parameters, locals);
    }

    private static LocalVariable local(String name, TypeRef type, long size) {
        return new LocalVariable(name, size, type, 0, true, "USER_DEFINED");
    }

    private static FunctionDeclaration declaration(String key, TypeRef result, List<Parameter> parameters) {
        return new FunctionDeclaration(key, "external", result, parameters,
            false, false, "default", "USER_DEFINED");
    }

    private static ProgramTypeModel model(TypeGraph graph, List<FunctionSignature> functions,
            List<VariableLocation> locations, List<FunctionStaticVariable> statics,
            List<LexicalScopeModel> scopes) {
        return new ProgramTypeModel(graph, functions, List.of(), new VariableStorageModel(locations),
            statics, List.of(), scopes);
    }

    private static void danglingReferences() {
        TypeGraph graph = graph();
        reject("missing return type", () -> new ProgramTypeModel(graph,
            List.of(function("function", ENTRY, MISSING, List.of(), List.of())), List.of()));
        reject("missing parameter type", () -> new ProgramTypeModel(graph,
            List.of(function(List.of(new Parameter("p", MISSING, false)), List.of())), List.of()));
        reject("missing local type", () -> new ProgramTypeModel(graph,
            List.of(function(List.of(), List.of(local("v", MISSING, 4)))), List.of()));
        reject("missing type for global", () -> new ProgramTypeModel(graph, List.of(),
            List.of(new GlobalVariable("g", 0, 4, MISSING, false, "USER_DEFINED"))));
        reject("missing type for function static", () -> model(graph,
            List.of(function(List.of(), List.of())), List.of(),
            List.of(new FunctionStaticVariable("s", 0x2000, 4, MISSING, ENTRY, "USER_DEFINED")), List.of()));
        reject("missing type for declaration", () -> new ProgramTypeModel(graph, List.of(), List.of(),
            new VariableStorageModel(List.of()), List.of(),
            List.of(declaration("external:1", INT, List.of(new Parameter("p", MISSING, false))))));
    }

    private static void objectParameters() {
        for (IndirectionKind kind : IndirectionKind.values()) {
            TypeRef pointer = new TypeRef("object-pointer");
            TypeRef alias = new TypeRef("object-alias");
            TypeRef qualified = new TypeRef("object-const");
            TypeGraph graph = new TypeGraph(List.of(graph().nodes().get(0),
                new IndirectionType(pointer.key(), "object pointer", 8, kind, INT),
                new TypedefType(alias.key(), "object alias", 8, pointer),
                new QualifiedType(qualified.key(), "const object alias", 8, List.of(Qualifier.CONST), alias)));
            for (TypeRef type : List.of(pointer, alias, qualified)) {
                Parameter object = new Parameter("this", type, true, false, true);
                var signature = function(List.of(object), List.of());
                var declaration = declaration("method", INT, List.of(object));
                var model = new ProgramTypeModel(graph, List.of(signature), List.of(),
                    new VariableStorageModel(List.of()), List.of(), List.of(declaration));
                check(model.functions().get(0).parameters().equals(List.of(object)),
                    "qualified object identity must survive normalization");
                check(model.functionDeclarations().get(0).parameters().equals(List.of(object)),
                    "declarations must retain the same object type");
            }
        }
        Parameter scalar = new Parameter("this", INT, true, false, true);
        reject("requires a pointer or reference", () -> new ProgramTypeModel(graph(),
            List.of(function(List.of(scalar), List.of())), List.of()));
        reject("requires a pointer or reference", () -> new ProgramTypeModel(graph(), List.of(), List.of(),
            new VariableStorageModel(List.of()), List.of(), List.of(declaration("method", INT, List.of(scalar)))));
        reject("multiple object parameters", () -> function(List.of(scalar, scalar), List.of()));
        reject("multiple object parameters", () -> declaration("method", INT, List.of(scalar, scalar)));
        TypeRef a = new TypeRef("a");
        TypeRef b = new TypeRef("b");
        TypeGraph cyclic = new TypeGraph(List.of(graph().nodes().get(0),
            new TypedefType("a", "alias", 8, b),
            new QualifiedType("b", "qualified alias", 8, List.of(Qualifier.CONST), a)));
        Parameter cycle = new Parameter("this", a, true, false, true);
        reject("cyclic object parameter", () -> new ProgramTypeModel(cyclic,
            List.of(function(List.of(cycle), List.of())), List.of()));
        reject("cyclic object parameter", () -> new ProgramTypeModel(cyclic, List.of(), List.of(),
            new VariableStorageModel(List.of()), List.of(), List.of(declaration("method", INT, List.of(cycle)))));
    }

    private static VariableLocation location(String function, long address, String name, VariableKind kind,
            long size, long start, long end) {
        return new VariableLocation(function, address, name, kind, size, List.of(new LocationRange(start, end,
            new MemoryStorage(0x3000), new Evidence(Confidence.USER_DEFINED, "explicit fixture memory"))));
    }

    private static void storageAgreement() {
        TypeRef padded = new TypeRef("padded-float");
        TypeRef alias = new TypeRef("alias");
        TypeGraph graph = new TypeGraph(List.of(graph().nodes().get(0),
            new BaseType(padded.key(), "extended float", 16, BaseEncoding.FLOAT, 10),
            new QualifiedType("qualified", "const extended float", 16, List.of(Qualifier.CONST), padded),
            new TypedefType(alias.key(), "extended alias", 16, new TypeRef("qualified")),
            new OpaqueType("opaque", "unknown", 0, "size unavailable")));
        var signature = function(List.of(new Parameter("p", alias, false)), List.of(local("v", INT, 4)));
        var parameter = location("function", ENTRY, "p", VariableKind.PARAMETER, 10, ENTRY, ENTRY + 16);
        var local = location("function", ENTRY, "v", VariableKind.LOCAL, 4, ENTRY, ENTRY + 16);
        var valid = model(graph, List.of(signature), List.of(local, parameter), List.of(), List.of());
        check(valid.variableStorage().variables().equals(List.of(parameter, local)),
            "value storage excludes floating ABI padding and keeps local size");
        for (long badSize : List.of(9L, 11L, 16L)) {
            reject("size differs from declaration", () -> model(graph, List.of(signature),
                List.of(location("function", ENTRY, "p", VariableKind.PARAMETER, badSize, ENTRY, ENTRY + 16)),
                List.of(), List.of()));
        }
        reject("size differs from declaration", () -> model(graph, List.of(signature),
            List.of(location("function", ENTRY, "v", VariableKind.LOCAL, 8, ENTRY, ENTRY + 16)), List.of(), List.of()));
        for (VariableKind kind : VariableKind.values()) {
            reject("has no declaration", () -> model(graph, List.of(signature),
                List.of(location("function", ENTRY, "absent", kind, 4, ENTRY, ENTRY + 16)), List.of(), List.of()));
            reject("missing function", () -> model(graph, List.of(signature),
                List.of(location("renamed", ENTRY, "p", kind, 10, ENTRY, ENTRY + 16)), List.of(), List.of()));
            reject("missing function", () -> model(graph, List.of(signature),
                List.of(location("function", ENTRY + 1, "p", kind, 10, ENTRY, ENTRY + 16)), List.of(), List.of()));
        }
        var opaque = function(List.of(new Parameter("p", new TypeRef("opaque"), false)), List.of());
        check(model(graph, List.of(opaque), List.of(parameter), List.of(), List.of())
            .variableStorage().variables().equals(List.of(parameter)), "unknown type size must not invent a contradiction");
    }

    private static LexicalScopeModel scope(long entry, List<LexicalScopeModel.Local> locals) {
        return new LexicalScopeModel(entry, List.of(new FunctionRange(entry, 32)),
            List.of(new LexicalScopeModel.Block("inner", "", List.of(new FunctionRange(entry + 8, 8)))),
            locals, "saved lexical scope");
    }

    private static void lexicalOwnership() {
        var local = local("saved", INT, 4);
        var signature = function(List.of(new Parameter("p", INT, false)), List.of(local));
        var scope = scope(ENTRY, List.of(new LexicalScopeModel.Local("saved", "inner", "p")));
        var storage = location("function", ENTRY, "saved", VariableKind.LOCAL, 4, ENTRY, ENTRY + 32);
        var parameter = location("function", ENTRY, "p", VariableKind.PARAMETER, 4, ENTRY, ENTRY + 32);
        var other = function("other", ENTRY + 0x100, INT, List.of(), List.of(local));
        var otherStorage = location("other", other.address(), "saved", VariableKind.LOCAL, 4,
            other.address(), other.address() + 32);
        var result = model(graph(), List.of(other, signature), List.of(otherStorage, storage, parameter),
            List.of(), List.of(scope));
        var restricted = result.variableStorage().variables().get(1);
        check(restricted.locations().equals(List.of(new LocationRange(ENTRY + 8, ENTRY + 16,
            storage.locations().get(0).storage(), storage.locations().get(0).evidence()))),
            "a local location must be intersected with its recorded block");
        check(result.variableStorage().variables().get(0).equals(parameter), "parameters retain their lifetime");
        check(result.variableStorage().variables().get(2).equals(otherStorage), "another function is not restricted");
        check(storage.locations().get(0).start() == ENTRY && storage.locations().get(0).end() == ENTRY + 32,
            "scope normalization must not mutate the caller's storage proof");
        var repeated = model(graph(), result.functions(), result.variableStorage().variables(), List.of(), List.of(scope));
        check(repeated.equals(result), "scope intersection must be idempotent");
        reject("duplicate lexical owner", () -> model(graph(), List.of(signature), List.of(), List.of(), List.of(scope, scope)));
        reject("missing lexical owner", () -> model(graph(), List.of(signature), List.of(), List.of(),
            List.of(scope(ENTRY + 1, List.of()))));
        reject("no unique canonical declaration", () -> model(graph(), List.of(signature), List.of(), List.of(),
            List.of(scope(ENTRY, List.of(new LexicalScopeModel.Local("absent", "inner", "v"))))));
        reject("no unique canonical declaration", () -> model(graph(),
            List.of(function(List.of(), List.of(local, local))), List.of(), List.of(), List.of(scope)));
        reject("ambiguous function-scope local", () -> model(graph(), List.of(signature), List.of(), List.of(),
            List.of(scope(ENTRY, List.of(new LexicalScopeModel.Local("saved", "", "p"))))));
        reject("ambiguous function-scope local", () -> model(graph(),
            List.of(function(List.of(new Parameter("saved", INT, false)), List.of(local))),
            List.of(), List.of(), List.of(scope(ENTRY, List.of()))));
        var renamed = scope(ENTRY, List.of(new LexicalScopeModel.Local("saved", "", "display")));
        check(model(graph(), List.of(signature), List.of(storage), List.of(), List.of(renamed))
            .variableStorage().variables().equals(List.of(storage)), "function-scope renaming preserves storage identity");
    }

    private static FunctionStaticVariable staticVariable(String name, long address, long owner, String block) {
        return new FunctionStaticVariable(name, address, 4, INT, owner, "USER_DEFINED", block);
    }

    private static void staticNames() {
        var signature = function(List.of(new Parameter("p", INT, false)), List.of(local("saved", INT, 4)));
        var scope = scope(ENTRY, List.of(new LexicalScopeModel.Local("saved", "inner", "v")));
        var outer = staticVariable("v", 0x2000, ENTRY, "");
        var inner = staticVariable("p", 0x2004, ENTRY, "inner");
        var other = function("other", ENTRY + 0x100, INT, List.of(), List.of());
        var distinctOwner = staticVariable("v", 0x2008, other.address(), "");
        var functions = List.of(signature, other);
        var valid = new ArrayList<>(List.of(outer, inner, distinctOwner));
        var first = model(graph(), functions, List.of(), valid, List.of(scope));
        Collections.reverse(valid);
        check(first.equals(model(graph(), List.of(other, signature), List.of(), valid, List.of(scope))),
            "static ordering and shadowing must be independent of extraction order");
        check(ProgramTypeModel.conflictingStatics(functions, List.of(scope), valid).isEmpty(),
            "parent shadowing and equal names in separate functions are valid");
        var parameterCollision = staticVariable("p", 0x2010, ENTRY, "");
        var localCollision = staticVariable("v", 0x2014, ENTRY, "inner");
        var duplicate = staticVariable("v", 0x2018, ENTRY, "");
        var conflicting = List.of(outer, parameterCollision, localCollision, duplicate);
        Set<FunctionStaticVariable> expected = Set.copyOf(conflicting);
        check(ProgramTypeModel.conflictingStatics(functions, List.of(scope), conflicting).equals(expected),
            "every conflicting static must be rejected, not just the later one");
        reject("ambiguous static name", () -> model(graph(), functions, List.of(), conflicting, List.of(scope)));
        reject("missing lexical owner for static", () -> model(graph(), functions, List.of(), List.of(inner), List.of()));
        reject("missing lexical owner for static", () -> model(graph(), functions, List.of(),
            List.of(staticVariable("s", 0x2010, ENTRY, "absent")), List.of(scope)));
        reject("ambiguous static name", () -> model(graph(), functions, List.of(),
            List.of(staticVariable("saved", 0x2010, ENTRY, "")), List.of()));
    }

    private static void callRestrictions() {
        for (boolean nonDefault : List.of(false, true)) {
            for (String restriction : List.of("", "unsupported calling convention")) {
                boolean disabled = nonDefault || !restriction.isEmpty();
                var signature = new FunctionSignature("function", ENTRY, INT, List.of(), List.of(),
                    false, false, "analyst convention", "USER_DEFINED", nonDefault, restriction, "effective convention");
                var declaration = new FunctionDeclaration("key", "function", INT, List.of(), false, false,
                    "analyst convention", "USER_DEFINED", nonDefault, restriction, "effective convention");
                check(signature.debuggerCallsDisabled() == disabled, "defined-function call restriction");
                check(declaration.debuggerCallsDisabled() == disabled, "external-function call restriction");
                check(signature.callingConvention().equals("analyst convention") &&
                    signature.effectiveCallingConvention().equals("effective convention"), "preserve both conventions");
            }
        }
    }

    private static void reject(String message, Runnable action) {
        try {
            action.run();
        }
        catch (IllegalArgumentException expected) {
            check(expected.getMessage().contains(message), "wrong rejection: " + expected.getMessage());
            return;
        }
        throw new AssertionError("accepted invalid model: " + message);
    }

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
