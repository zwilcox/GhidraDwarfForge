package ghidradwarfforge.types;

import java.util.Comparator;
import java.util.List;

import ghidradwarfforge.locations.VariableStorageModel;
import ghidradwarfforge.locations.VariableStorageModel.VariableKind;
import ghidradwarfforge.locations.VariableStorageModel.VariableLocation;
import ghidradwarfforge.types.TypeGraph.Parameter;
import ghidradwarfforge.types.TypeGraph.TypeRef;

/** Curated function signatures and the canonical types they reference. */
public record ProgramTypeModel(TypeGraph types, List<FunctionSignature> functions,
        List<GlobalVariable> globals, VariableStorageModel variableStorage,
        List<FunctionStaticVariable> functionStatics,
        List<FunctionDeclaration> functionDeclarations, List<LexicalScopeModel> lexicalScopes,
        ClassScopeModel classScopes) {
    public ProgramTypeModel(TypeGraph types, List<FunctionSignature> functions,
            List<GlobalVariable> globals, VariableStorageModel variableStorage,
            List<FunctionStaticVariable> functionStatics, List<FunctionDeclaration> functionDeclarations,
            List<LexicalScopeModel> lexicalScopes) {
        this(types, functions, globals, variableStorage, functionStatics, functionDeclarations,
            lexicalScopes, ClassScopeModel.empty());
    }

    public ProgramTypeModel(TypeGraph types, List<FunctionSignature> functions,
            List<GlobalVariable> globals, VariableStorageModel variableStorage,
            List<FunctionStaticVariable> functionStatics, List<FunctionDeclaration> functionDeclarations) {
        this(types, functions, globals, variableStorage, functionStatics, functionDeclarations, List.of());
    }

    public ProgramTypeModel(TypeGraph types, List<FunctionSignature> functions,
            List<GlobalVariable> globals, VariableStorageModel variableStorage,
            List<FunctionStaticVariable> functionStatics) {
        this(types, functions, globals, variableStorage, functionStatics, List.of());
    }

    public ProgramTypeModel(TypeGraph types, List<FunctionSignature> functions,
            List<GlobalVariable> globals, VariableStorageModel variableStorage) {
        this(types, functions, globals, variableStorage, List.of());
    }

    public ProgramTypeModel(TypeGraph types, List<FunctionSignature> functions,
            List<GlobalVariable> globals) {
        this(types, functions, globals, new VariableStorageModel(List.of()));
    }

    public record GlobalVariable(String name, long address, long size, TypeRef type,
            boolean declaration, String source, List<String> namespace) {
        public GlobalVariable(String name, long address, long size, TypeRef type,
                boolean declaration, String source) {
            this(name, address, size, type, declaration, source, List.of());
        }

        public GlobalVariable {
            if (name == null || name.isBlank() || address < 0 || size <= 0 ||
                    type == null || source == null || namespace == null ||
                    namespace.stream().anyMatch(part -> part == null || part.isBlank())) {
                throw new IllegalArgumentException("invalid global variable");
            }
            namespace = List.copyOf(namespace);
        }
    }

    /** A defined memory object with evidence-backed function and optional lexical ownership. */
    public record FunctionStaticVariable(String name, long address, long size, TypeRef type,
            long ownerAddress, String source, String block) {
        public FunctionStaticVariable(String name, long address, long size, TypeRef type,
                long ownerAddress, String source) {
            this(name, address, size, type, ownerAddress, source, "");
        }

        public FunctionStaticVariable {
            if (name == null || name.isBlank() || address < 0 || size <= 0 ||
                    type == null || ownerAddress < 0 || source == null || source.isBlank() || block == null) {
                throw new IllegalArgumentException("invalid function-owned static variable");
            }
        }
    }

    public record FunctionSignature(String name, long address, TypeRef returnType,
            List<Parameter> parameters, List<LocalVariable> locals, boolean variadic,
            boolean noReturn, String callingConvention, String signatureSource,
            boolean nonDefaultCallingConvention, String debuggerCallRestriction) {
        public FunctionSignature {
            if (name == null || name.isBlank() || address < 0 || returnType == null ||
                    parameters == null || locals == null || callingConvention == null ||
                    signatureSource == null || debuggerCallRestriction == null) {
                throw new IllegalArgumentException("invalid function signature");
            }
            parameters = List.copyOf(parameters);
            validateObjectParameterCount(parameters);
            locals = locals.stream()
                .sorted(Comparator.comparingInt(LocalVariable::firstUseOffset)
                    .thenComparing(LocalVariable::name))
                .toList();
        }

        public boolean debuggerCallsDisabled() {
            return nonDefaultCallingConvention || !debuggerCallRestriction.isEmpty();
        }

        public FunctionSignature(String name, long address, TypeRef returnType,
                List<Parameter> parameters, List<LocalVariable> locals, boolean variadic,
                boolean noReturn, String callingConvention, String signatureSource,
                boolean nonDefaultCallingConvention) {
            this(name, address, returnType, parameters, locals, variadic, noReturn,
                callingConvention, signatureSource, nonDefaultCallingConvention, "");
        }

        public FunctionSignature(String name, long address, TypeRef returnType,
                List<Parameter> parameters, List<LocalVariable> locals, boolean variadic,
                boolean noReturn, String callingConvention, String signatureSource) {
            this(name, address, returnType, parameters, locals, variadic, noReturn,
                callingConvention, signatureSource, false);
        }
    }

    /** A curated external signature with an identity key, never an image address. */
    public record FunctionDeclaration(String key, String name, TypeRef returnType,
            List<Parameter> parameters, boolean variadic, boolean noReturn,
            String callingConvention, String signatureSource, boolean nonDefaultCallingConvention,
            String debuggerCallRestriction) {
        public FunctionDeclaration {
            if (key == null || key.isBlank() || name == null || name.isBlank() ||
                    returnType == null || parameters == null || callingConvention == null ||
                    signatureSource == null || signatureSource.isBlank() || debuggerCallRestriction == null) {
                throw new IllegalArgumentException("invalid external function declaration");
            }
            parameters = List.copyOf(parameters);
            validateObjectParameterCount(parameters);
        }

        public boolean debuggerCallsDisabled() {
            return nonDefaultCallingConvention || !debuggerCallRestriction.isEmpty();
        }

        public FunctionDeclaration(String key, String name, TypeRef returnType,
                List<Parameter> parameters, boolean variadic, boolean noReturn,
                String callingConvention, String signatureSource, boolean nonDefaultCallingConvention) {
            this(key, name, returnType, parameters, variadic, noReturn, callingConvention,
                signatureSource, nonDefaultCallingConvention, "");
        }

        public FunctionDeclaration(String key, String name, TypeRef returnType,
                List<Parameter> parameters, boolean variadic, boolean noReturn,
                String callingConvention, String signatureSource) {
            this(key, name, returnType, parameters, variadic, noReturn,
                callingConvention, signatureSource, false);
        }
    }

    /** A recovered local declaration. Location emission is deliberately separate. */
    public record LocalVariable(String name, long byteSize, TypeRef type,
            int firstUseOffset, boolean storageAssigned, String source) {
        public LocalVariable {
            if (name == null || name.isBlank() || byteSize <= 0 || type == null ||
                    source == null || source.isBlank()) {
                throw new IllegalArgumentException("invalid local variable");
            }
        }
    }

    private static void validateObjectParameterCount(List<Parameter> parameters) {
        if (parameters.stream().filter(Parameter::objectPointer).count() > 1) {
            throw new IllegalArgumentException("multiple object parameters in one signature");
        }
    }

    private static void validateObjectParameterTypes(TypeGraph types, List<Parameter> parameters) {
        for (Parameter parameter : parameters) {
            if (!parameter.objectPointer()) {
                continue;
            }
            var byKey = types.byKey();
            var visited = new java.util.HashSet<String>();
            TypeRef reference = parameter.type();
            while (visited.add(reference.key())) {
                var node = byKey.get(reference.key());
                if (node instanceof TypeGraph.QualifiedType qualified) {
                    reference = qualified.target();
                }
                else if (node instanceof TypeGraph.TypedefType typedef) {
                    reference = typedef.target();
                }
                else {
                    if (!(node instanceof TypeGraph.IndirectionType)) {
                        throw new IllegalArgumentException("object parameter requires a pointer or reference type");
                    }
                    break;
                }
            }
            if (!(byKey.get(reference.key()) instanceof TypeGraph.IndirectionType)) {
                throw new IllegalArgumentException("cyclic object parameter type");
            }
        }
    }

    public ProgramTypeModel {
        if (types == null || functions == null || globals == null || variableStorage == null ||
                functionStatics == null || functionDeclarations == null) {
            throw new IllegalArgumentException(
                "types/functions/globals/variable storage/function statics are required");
        }
        functions = functions.stream()
            .sorted(Comparator.comparingLong(FunctionSignature::address)
                .thenComparing(FunctionSignature::name))
            .toList();
        globals = globals.stream()
            .sorted(Comparator.comparingLong(GlobalVariable::address)
                .thenComparing(global -> String.join("\u0000", global.namespace()))
                .thenComparing(GlobalVariable::name))
            .toList();
        functionStatics = functionStatics.stream()
            .sorted(Comparator.comparingLong(FunctionStaticVariable::ownerAddress)
                .thenComparing(FunctionStaticVariable::block)
                .thenComparing(FunctionStaticVariable::name)
                .thenComparingLong(FunctionStaticVariable::address))
            .toList();
        functionDeclarations = functionDeclarations.stream()
            .sorted(Comparator.comparing(FunctionDeclaration::name)
                .thenComparing(FunctionDeclaration::key))
            .toList();
        var declarationKeys = new java.util.HashSet<String>();
        for (FunctionDeclaration declaration : functionDeclarations) {
            validateObjectParameterTypes(types, declaration.parameters());
            if (!declarationKeys.add(declaration.key()) ||
                    !types.byKey().containsKey(declaration.returnType().key()) ||
                    declaration.parameters().stream().anyMatch(parameter ->
                        !types.byKey().containsKey(parameter.type().key()))) {
                throw new IllegalArgumentException("duplicate identity or missing type for declaration " +
                    declaration.name());
            }
        }
        for (FunctionSignature function : functions) {
            validateObjectParameterTypes(types, function.parameters());
            if (!types.byKey().containsKey(function.returnType().key())) {
                throw new IllegalArgumentException("missing return type for " + function.name());
            }
            for (Parameter parameter : function.parameters()) {
                if (!types.byKey().containsKey(parameter.type().key())) {
                    throw new IllegalArgumentException(
                        "missing parameter type for " + function.name());
                }
            }
            for (LocalVariable local : function.locals()) {
                if (!types.byKey().containsKey(local.type().key())) {
                    throw new IllegalArgumentException(
                        "missing local type for " + function.name() + "::" + local.name());
                }
            }
        }
        for (GlobalVariable global : globals) {
            if (!types.byKey().containsKey(global.type().key())) {
                throw new IllegalArgumentException("missing type for global " + global.name());
            }
        }
        java.util.Set<Long> owners = functions.stream().map(FunctionSignature::address)
            .collect(java.util.stream.Collectors.toSet());
        for (FunctionStaticVariable variable : functionStatics) {
            if (!owners.contains(variable.ownerAddress())) {
                throw new IllegalArgumentException("missing function owner for " + variable.name());
            }
            if (!types.byKey().containsKey(variable.type().key())) {
                throw new IllegalArgumentException("missing type for function static " +
                    variable.name());
            }
        }
        if (classScopes == null) throw new IllegalArgumentException("class scopes are required");
        classScopes.validate(types, functions, functionDeclarations);
        if (lexicalScopes == null) throw new IllegalArgumentException("lexical scopes are required");
        lexicalScopes = lexicalScopes.stream().sorted(Comparator.comparingLong(LexicalScopeModel::functionAddress)).toList();
        var scopedOwners = new java.util.HashMap<Long, LexicalScopeModel>();
        for (var scope : lexicalScopes) {
            if (scopedOwners.put(scope.functionAddress(), scope) != null) throw new IllegalArgumentException("duplicate lexical owner");
            var function = functions.stream().filter(f -> f.address() == scope.functionAddress()).findFirst()
                .orElseThrow(() -> new IllegalArgumentException("missing lexical owner"));
            var names = new java.util.HashSet<String>();
            function.parameters().forEach(parameter -> names.add(parameter.name()));
            for (var local : function.locals()) {
                var binding = scope.local(local.name());
                if ((binding == null || binding.block().isEmpty()) &&
                        !names.add(binding == null ? local.name() : binding.displayName())) {
                    throw new IllegalArgumentException("ambiguous function-scope local");
                }
            }
            for (var local : scope.locals()) {
                if (function.locals().stream().filter(v -> v.name().equals(local.savedName())).count() != 1) {
                    throw new IllegalArgumentException("scoped local has no unique canonical declaration");
                }
            }
        }
        if (!scopedOwners.isEmpty()) {
            var restricted = variableStorage.variables().stream().map(location -> {
                var scope = scopedOwners.get(location.functionAddress());
                return scope == null || location.kind() != VariableKind.LOCAL ? location : scope.restrict(location);
            }).toList();
            if (!restricted.equals(variableStorage.variables())) {
                variableStorage = new VariableStorageModel(restricted);
            }
        }
        for (var variable : functionStatics) {
            var scope = scopedOwners.get(variable.ownerAddress());
            if (!variable.block().isEmpty() && (scope == null || scope.blocks().stream()
                    .noneMatch(block -> block.id().equals(variable.block())))) {
                throw new IllegalArgumentException("missing lexical owner for static " + variable.name());
            }
        }
        if (!conflictingStatics(functions, lexicalScopes, functionStatics).isEmpty()) {
            throw new IllegalArgumentException("ambiguous static name in its recorded scope");
        }
        for (VariableLocation location : variableStorage.variables()) {
            FunctionSignature function = functions.stream()
                .filter(candidate -> candidate.address() == location.functionAddress() &&
                    candidate.name().equals(location.functionName()))
                .findFirst().orElseThrow(() -> new IllegalArgumentException(
                    "variable location refers to missing function " +
                        location.functionName()));
            long declaredSize = location.kind() == VariableKind.PARAMETER
                ? function.parameters().stream()
                    .filter(parameter -> parameter.name().equals(location.name()))
                    .map(parameter -> types.byKey().get(parameter.type().key()).byteSize())
                    .findFirst().orElse(-1L)
                : function.locals().stream()
                    .filter(local -> local.name().equals(location.name()))
                    .mapToLong(LocalVariable::byteSize).findFirst().orElse(-1L);
            if (declaredSize < 0) {
                throw new IllegalArgumentException("variable location has no declaration " +
                    location.functionName() + "::" + location.name());
            }
            if (declaredSize > 0 && declaredSize != location.byteSize()) {
                throw new IllegalArgumentException("variable location size differs from " +
                    "declaration " + location.functionName() + "::" + location.name());
            }
        }
    }

    /** Reject every conflicting static, independently of extraction order. Parent shadowing is valid. */
    public static java.util.Set<FunctionStaticVariable> conflictingStatics(List<FunctionSignature> functions,
            List<LexicalScopeModel> scopes, List<FunctionStaticVariable> statics) {
        record Name(long owner, String block, String spelling) { }
        var counts = new java.util.HashMap<Name, Integer>();
        for (var function : functions) {
            var scope = scopes.stream().filter(s -> s.functionAddress() == function.address()).findFirst().orElse(null);
            for (var parameter : function.parameters()) {
                counts.merge(new Name(function.address(), "", parameter.name()), 1, Integer::sum);
            }
            for (var local : function.locals()) {
                var binding = scope == null ? null : scope.local(local.name());
                counts.merge(new Name(function.address(), binding == null ? "" : binding.block(),
                    binding == null ? local.name() : binding.displayName()), 1, Integer::sum);
            }
        }
        for (var variable : statics) {
            counts.merge(new Name(variable.ownerAddress(), variable.block(), variable.name()), 1, Integer::sum);
        }
        return statics.stream().filter(variable -> counts.get(new Name(variable.ownerAddress(), variable.block(),
            variable.name())) > 1).collect(java.util.stream.Collectors.toUnmodifiableSet());
    }
}
