package ghidradwarfforge.types;

import java.util.*;

import ghidradwarfforge.locations.VariableStorageModel;
import ghidradwarfforge.types.ProgramTypeModel.*;
import ghidradwarfforge.types.TypeGraph.*;

/** Declaration admission and immutable snapshots before native producer calls. */
final class ProgramDeclarationBoundarySmoke {
    private static final TypeRef INT = new TypeRef("int");
    private static final String SOURCE = "USER_DEFINED";
    private static int checks;

    private ProgramDeclarationBoundarySmoke() { }

    static void run() {
        invalidIdentities();
        invalidGeometryAndTypes();
        missingSignatureFields();
        missingModelComponents();
        snapshotAndOrdering();
        declarationWithoutLocation();
        System.out.println("program-declaration-boundaries=PASS checks=" + checks);
    }

    private static void invalidIdentities() {
        for (String name : Arrays.asList(null, "", " \t\n")) {
            reject("invalid global variable", () -> new GlobalVariable(name, 0, 4, INT, false, SOURCE));
            reject("invalid function-owned static variable", () -> new FunctionStaticVariable(name, 0, 4, INT, 0, SOURCE));
            reject("invalid function signature", () -> new FunctionSignature(name, 0, INT, List.of(), List.of(), false, false, "", SOURCE));
            reject("invalid external function declaration", () -> new FunctionDeclaration("external:1", name, INT, List.of(), false, false, "", SOURCE));
            reject("invalid local variable", () -> new LocalVariable(name, 4, INT, 0, false, SOURCE));
            reject("invalid external function declaration", () -> new FunctionDeclaration(name, "external", INT, List.of(), false, false, "", SOURCE));
        }
        for (List<String> namespace : Arrays.asList((List<String>) null, Arrays.asList("outer", null), List.of("outer", ""), List.of(" "))) {
            reject("invalid global variable", () -> new GlobalVariable("g", 0, 4, INT, false, SOURCE, namespace));
        }
        for (String source : Arrays.asList(null, "", " \t")) {
            reject("invalid function-owned static variable", () -> new FunctionStaticVariable("s", 0, 4, INT, 0, source));
            reject("invalid external function declaration", () -> new FunctionDeclaration("external:1", "external", INT, List.of(), false, false, "", source));
            reject("invalid local variable", () -> new LocalVariable("v", 4, INT, 0, false, source));
        }
        reject("invalid global variable", () -> new GlobalVariable("g", 0, 4, INT, false, null));
        reject("invalid function-owned static variable", () -> new FunctionStaticVariable("s", 0, 4, INT, 0, SOURCE, null));
    }

    private static void invalidGeometryAndTypes() {
        // Negative sentinel addresses and nonpositive extents have no admitted image identity.
        for (long size : List.of(-1L, 0L)) {
            reject("invalid global variable", () -> new GlobalVariable("g", 0, size, INT, false, SOURCE));
            reject("invalid function-owned static variable", () -> new FunctionStaticVariable("s", 0, size, INT, 0, SOURCE));
            reject("invalid local variable", () -> new LocalVariable("v", size, INT, 0, false, SOURCE));
        }
        reject("invalid global variable", () -> new GlobalVariable("g", -1, 4, INT, false, SOURCE));
        reject("invalid function-owned static variable", () -> new FunctionStaticVariable("s", -1, 4, INT, 0, SOURCE));
        reject("invalid global variable", () -> new GlobalVariable("g", 0, 4, null, false, SOURCE));
        reject("invalid function-owned static variable", () -> new FunctionStaticVariable("s", 0, 4, null, 0, SOURCE));
        reject("invalid local variable", () -> new LocalVariable("v", 4, null, 0, false, SOURCE));
        for (long address : List.of(0L, 0x1_0000_0000L, Long.MAX_VALUE, Long.MIN_VALUE, -1L)) {
            var global = new GlobalVariable("g", address, 1, INT, false, SOURCE);
            var local = new LocalVariable("v", 1, INT, -1, false, SOURCE);
            var signature = new FunctionSignature("f", address, INT, List.of(), List.of(local), false, false, "", "");
            var functionStatic = new FunctionStaticVariable("s", address, 1, INT, address, SOURCE);
            check(global.address() == address && global.size() == 1, "retain exact global address and positive extent");
            check(signature.address() == address && signature.locals().getFirst().firstUseOffset() == -1,
                "retain exact definition address and saved local first-use offset");
            check(functionStatic.address() == address && functionStatic.ownerAddress() == address,
                "retain exact static identity and owner without narrowing");
        }
    }

    private static void missingSignatureFields() {
        for (int missing = 0; missing < 7; missing++) {
            int field = missing;
            reject("invalid function signature", () -> new FunctionSignature("f", 0, field == 0 ? null : INT,
                field == 1 ? null : List.of(), field == 2 ? null : List.of(), false, false,
                field == 3 ? null : "", field == 4 ? null : SOURCE, false, field == 5 ? null : "", field == 6 ? null : ""));
        }
        for (int missing = 0; missing < 6; missing++) {
            int field = missing;
            reject("invalid external function declaration", () -> new FunctionDeclaration("external:1", "external", field == 0 ? null : INT,
                field == 1 ? null : List.of(), false, false, field == 2 ? null : "", field == 3 ? null : SOURCE,
                false, field == 4 ? null : "", field == 5 ? null : ""));
        }
        // Unknown convention/provenance text is retained where this record permits it.
        var signature = new FunctionSignature(" f ", 0, INT, List.of(), List.of(), true, true, "", "", false, "", "");
        check(signature.name().equals(" f ") && signature.callingConvention().isEmpty() &&
            signature.signatureSource().isEmpty() && signature.effectiveCallingConvention().isEmpty() &&
            signature.variadic() && signature.noReturn(), "preserve unknown fields and exact analyst name");
        var global = new GlobalVariable(" g ", 0, 4, INT, true, "", List.of("分析", "Analyst Space"));
        check(global.name().equals(" g ") && global.declaration() && global.source().isEmpty() &&
            global.namespace().equals(List.of("分析", "Analyst Space")), "retain global provenance, declaration flag and namespace spelling");
        var declaration = new FunctionDeclaration("library:9", " f ", INT, List.of(), true, true, "analyst convention", SOURCE,
            true, "unsafe injected call", "effective convention");
        check(declaration.key().equals("library:9") && declaration.name().equals(" f ") && declaration.variadic() && declaration.noReturn() &&
            declaration.callingConvention().equals("analyst convention") && declaration.effectiveCallingConvention().equals("effective convention") &&
            declaration.debuggerCallsDisabled() && declaration.debuggerCallRestriction().equals("unsafe injected call"),
            "external identity, distinct conventions and call restrictions remain exact");
    }

    private static void missingModelComponents() {
        for (int missing = 0; missing < 9; missing++) {
            int field = missing;
            String message = missing < 6 ? "types/functions/globals/variable storage/function statics are required" :
                missing == 6 ? "lexical scopes are required" : missing == 7 ? "class scopes are required" : "function relationships are required";
            reject(message, () -> new ProgramTypeModel(field == 0 ? null : graph(), field == 1 ? null : List.of(),
                field == 2 ? null : List.of(), field == 3 ? null : new VariableStorageModel(List.of()),
                field == 4 ? null : List.of(), field == 5 ? null : List.of(), field == 6 ? null : List.of(),
                field == 7 ? null : ClassScopeModel.empty(), field == 8 ? null : FunctionRelations.empty()));
        }
        var empty = new ProgramTypeModel(graph(), List.of(), List.of());
        check(empty.functions().isEmpty() && empty.globals().isEmpty() && empty.variableStorage().variables().isEmpty() &&
            empty.functionStatics().isEmpty() && empty.functionDeclarations().isEmpty() && empty.lexicalScopes().isEmpty(),
            "explicitly empty model is valid and invents no declarations or locations");
    }

    private static void snapshotAndOrdering() {
        var namespace = new ArrayList<>(List.of("outer", "分析"));
        var global = new GlobalVariable("g", 0x2000, 4, INT, false, SOURCE, namespace);
        namespace.set(1, "changed");
        check(global.namespace().equals(List.of("outer", "分析")), "global namespace owns an immutable snapshot");
        immutable(() -> global.namespace().add("changed"));
        var parameters = new ArrayList<>(List.of(new Parameter("z", INT, false), new Parameter("a", INT, false)));
        var early = new LocalVariable("z_early", 4, INT, -1, false, SOURCE);
        var tiedA = new LocalVariable("a_tied", 4, INT, 8, true, SOURCE);
        var tiedZ = new LocalVariable("z_tied", 4, INT, 8, false, SOURCE);
        var locals = new ArrayList<>(List.of(tiedZ, early, tiedA));
        var signature = new FunctionSignature("f", 0x1000, INT, parameters, locals, true, false, "", SOURCE);
        var declaration = new FunctionDeclaration("external:2", "overloaded", INT, parameters, false, true, "", SOURCE);
        check(locals.equals(List.of(tiedZ, early, tiedA)), "canonicalization does not sort caller-owned locals in place");
        parameters.clear(); locals.clear();
        check(signature.parameters().stream().map(Parameter::name).toList().equals(List.of("z", "a")) &&
            declaration.parameters().equals(signature.parameters()), "parameter ABI order survives caller list mutation");
        check(signature.locals().equals(List.of(early, tiedA, tiedZ)), "local order uses first use, then name");
        immutable(() -> signature.parameters().clear());
        immutable(() -> signature.locals().clear());
        immutable(() -> declaration.parameters().clear());
        var later = new FunctionSignature("later", 0x2000, INT, List.of(), List.of(), false, false, "", SOURCE);
        var overload = new FunctionDeclaration("external:1", "overloaded", INT, List.of(), false, false, "", SOURCE);
        var namespaced = new GlobalVariable("same-address", 0x2000, 4, INT, false, SOURCE, List.of("a"));
        var lower = new GlobalVariable("lower", 0x1000, 4, INT, false, SOURCE);
        var staticA = new FunctionStaticVariable("a_static", 0x4004, 4, INT, signature.address(), SOURCE);
        var staticZ = new FunctionStaticVariable("z_static", 0x4000, 4, INT, signature.address(), SOURCE);
        var functions = new ArrayList<>(List.of(later, signature));
        var globals = new ArrayList<>(List.of(global, namespaced, lower));
        var statics = new ArrayList<>(List.of(staticZ, staticA));
        var declarations = new ArrayList<>(List.of(declaration, overload));
        var model = new ProgramTypeModel(graph(), functions, globals, new VariableStorageModel(List.of()), statics, declarations);
        check(functions.equals(List.of(later, signature)) && globals.equals(List.of(global, namespaced, lower)) &&
            statics.equals(List.of(staticZ, staticA)) && declarations.equals(List.of(declaration, overload)), "model construction preserves all caller ordering");
        functions.clear(); globals.clear(); statics.clear(); declarations.clear();
        check(model.functions().equals(List.of(signature, later)), "functions retain ascending image order");
        check(model.globals().equals(List.of(lower, namespaced, global)), "globals retain address and namespace order");
        check(model.functionStatics().equals(List.of(staticA, staticZ)), "static identity order retains owner and name");
        check(model.functionDeclarations().equals(List.of(overload, declaration)), "same-spelled external functions retain distinct ordered keys");
        immutable(() -> model.functions().clear());
        immutable(() -> model.globals().clear());
        immutable(() -> model.functionStatics().clear());
        immutable(() -> model.functionDeclarations().clear());
        var reversedFunctions = new ArrayList<>(model.functions()); Collections.reverse(reversedFunctions);
        var reversedGlobals = new ArrayList<>(model.globals()); Collections.reverse(reversedGlobals);
        var reversedStatics = new ArrayList<>(model.functionStatics()); Collections.reverse(reversedStatics);
        var reversedDeclarations = new ArrayList<>(model.functionDeclarations()); Collections.reverse(reversedDeclarations);
        check(model.equals(new ProgramTypeModel(graph(), reversedFunctions, reversedGlobals, new VariableStorageModel(List.of()),
            reversedStatics, reversedDeclarations)), "model independent of extraction order");
    }

    private static void declarationWithoutLocation() {
        for (boolean assigned : List.of(false, true)) {
            for (int firstUse : List.of(Integer.MIN_VALUE, -1, 0, Integer.MAX_VALUE)) {
                var local = new LocalVariable("saved", 4, INT, firstUse, assigned, SOURCE);
                var function = new FunctionSignature("owner", 0, INT, List.of(), List.of(local), false, false, "", SOURCE);
                var model = new ProgramTypeModel(graph(), List.of(function), List.of());
                check(model.functions().getFirst().locals().equals(List.of(local)), "saved local declaration retains offset and storage hint");
                check(model.variableStorage().variables().isEmpty(), "declaration and assigned-storage hint cannot fabricate a location");
            }
        }
    }

    private static TypeGraph graph() { return new TypeGraph(List.of(new BaseType("int", "int", 4, BaseEncoding.SIGNED))); }
    private static void reject(String message, Runnable operation) {
        try { operation.run(); throw new AssertionError("invalid declaration admitted: " + message); }
        catch (IllegalArgumentException expected) { check(expected.getMessage().equals(message), "specific declaration rejection: " + expected); }
    }
    private static void immutable(Runnable operation) {
        try { operation.run(); throw new AssertionError("saved declaration collection is mutable"); }
        catch (UnsupportedOperationException expected) { checks++; }
    }
    private static void check(boolean condition, String message) { if (!condition) throw new AssertionError(message); checks++; }
}
