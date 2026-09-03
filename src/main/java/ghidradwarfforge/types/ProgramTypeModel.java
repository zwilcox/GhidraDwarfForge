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
        List<GlobalVariable> globals, VariableStorageModel variableStorage) {
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

    public record FunctionSignature(String name, long address, TypeRef returnType,
            List<Parameter> parameters, List<LocalVariable> locals, boolean variadic,
            boolean noReturn, String callingConvention, String signatureSource) {
        public FunctionSignature {
            if (name == null || name.isBlank() || address < 0 || returnType == null ||
                    parameters == null || locals == null || callingConvention == null ||
                    signatureSource == null) {
                throw new IllegalArgumentException("invalid function signature");
            }
            parameters = List.copyOf(parameters);
            locals = locals.stream()
                .sorted(Comparator.comparingInt(LocalVariable::firstUseOffset)
                    .thenComparing(LocalVariable::name))
                .toList();
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

    public ProgramTypeModel {
        if (types == null || functions == null || globals == null || variableStorage == null) {
            throw new IllegalArgumentException(
                "types/functions/globals/variable storage are required");
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
        for (FunctionSignature function : functions) {
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
}
