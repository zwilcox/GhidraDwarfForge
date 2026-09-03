package ghidradwarfforge;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import ghidra.program.model.data.AbstractFloatDataType;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Dynamic;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.data.WideChar16DataType;
import ghidra.program.model.data.WideChar32DataType;
import ghidra.program.model.data.WideCharDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.UniversalID;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalLocationIterator;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel;
import ghidradwarfforge.locations.VariableStorageModel.Confidence;
import ghidradwarfforge.locations.VariableStorageModel.RegisterRelativeStorage;
import ghidradwarfforge.locations.VariableStorageModel.RegisterStorage;
import ghidradwarfforge.locations.VariableStorageModel.StackStorage;
import ghidradwarfforge.locations.VariableStorageModel.Evidence;
import ghidradwarfforge.locations.VariableStorageModel.LocationRange;
import ghidradwarfforge.locations.VariableStorageModel.OmissionReason;
import ghidradwarfforge.locations.VariableStorageModel.Storage;
import ghidradwarfforge.locations.VariableStorageModel.UnavailableStorage;
import ghidradwarfforge.locations.VariableStorageModel.VariableKind;
import ghidradwarfforge.locations.VariableStorageModel.VariableLocation;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.TypeGraph;
import ghidradwarfforge.types.TypeGraph.AggregateKind;
import ghidradwarfforge.types.TypeGraph.AggregateType;
import ghidradwarfforge.types.TypeGraph.ArrayType;
import ghidradwarfforge.types.TypeGraph.BaseEncoding;
import ghidradwarfforge.types.TypeGraph.BaseType;
import ghidradwarfforge.types.TypeGraph.EnumType;
import ghidradwarfforge.types.TypeGraph.Enumerator;
import ghidradwarfforge.types.TypeGraph.IndirectionKind;
import ghidradwarfforge.types.TypeGraph.IndirectionType;
import ghidradwarfforge.types.TypeGraph.Member;
import ghidradwarfforge.types.TypeGraph.OpaqueType;
import ghidradwarfforge.types.TypeGraph.SubroutineType;
import ghidradwarfforge.types.TypeGraph.TypeNode;
import ghidradwarfforge.types.TypeGraph.TypeRef;
import ghidradwarfforge.types.TypeGraph.TypedefType;
import ghidradwarfforge.types.TypeGraph.VoidType;

/** Extracts Ghidra's curated listing signatures into a cycle-safe type graph. */
public final class GhidraTypeGraph {
    private GhidraTypeGraph() {
    }

    public static ProgramTypeModel extract(Program program,
            List<FunctionSymbol> exportedFunctions, String targetName, long rebaseDelta,
            TaskMonitor monitor, Consumer<String> diagnostic) throws CancelledException {
        Extractor extractor = new Extractor(diagnostic);
        TargetRegisterMap registerMap = TargetRegisterMap.forTarget(targetName);
        List<DataType> favoriteTypes = new ArrayList<>(
            program.getDataTypeManager().getFavorites());
        favoriteTypes.sort(Comparator.comparing(DataType::getPathName)
            .thenComparing(type -> type.getClass().getName()));
        for (DataType favorite : favoriteTypes) {
            extractor.reserve(favorite);
        }
        Map<Long, FunctionSymbol> selected = new HashMap<>();
        for (FunctionSymbol symbol : exportedFunctions) {
            selected.put(symbol.address(), symbol);
        }
        List<ProgramTypeModel.FunctionSignature> signatures = new ArrayList<>();
        List<VariableLocation> variableLocations = new ArrayList<>();
        FunctionIterator functions = program.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            monitor.checkCancelled();
            Function function = functions.next();
            long address;
            try {
                address = AddressNormalizer.toElfAddress(
                    function.getEntryPoint().getOffset(), rebaseDelta);
            }
            catch (ArithmeticException overflow) {
                continue;
            }
            FunctionSymbol symbol = selected.remove(address);
            if (symbol == null) {
                continue;
            }
            GhidraVariableStorage.StackDepthProfile stackDepths =
                GhidraVariableStorage.stackDepthProfile(program, function, monitor);
            TypeRef returnType = extractor.reserve(function.getReturnType());
            List<TypeGraph.Parameter> parameters = new ArrayList<>();
            for (Parameter parameter : function.getParameters()) {
                DataType formalType = parameter.getFormalDataType();
                int logicalLength = formalType == null ? parameter.getLength()
                    : formalType.getLength();
                String parameterName = safeParameterName(parameter);
                parameters.add(new TypeGraph.Parameter(parameterName,
                    extractor.reserve(formalType), parameter.isAutoParameter()));
                if (!parameterName.isBlank() && logicalLength > 0) {
                    Storage storage = GhidraVariableStorage.stableParameter(program, function,
                        parameter, registerMap, monitor);
                    List<LocationRange> ranges = locationRanges(symbol, storage, stackDepths,
                        registerMap, rebaseDelta, parameter.getSource());
                    variableLocations.add(new VariableLocation(symbol.name(), address,
                        parameterName, VariableKind.PARAMETER, logicalLength, ranges));
                    if (storage instanceof UnavailableStorage unavailable) {
                        diagnostic.accept("Omitted location for " + symbol.name() + "::" +
                            parameterName + ": " + unavailable.diagnostic());
                    }
                }
            }
            List<ProgramTypeModel.LocalVariable> locals = new ArrayList<>();
            for (Variable variable : function.getLocalVariables()) {
                monitor.checkCancelled();
                String localName = variable.getName();
                if (localName == null || localName.isBlank() || variable.getLength() <= 0) {
                    diagnostic.accept("Skipped unnamed or zero-size local in " + symbol.name());
                    continue;
                }
                locals.add(new ProgramTypeModel.LocalVariable(localName,
                    variable.getLength(), extractor.reserve(variable.getDataType()),
                    variable.getFirstUseOffset(), variable.hasAssignedStorage(),
                    variable.getSource().name()));
                Storage storage = GhidraVariableStorage.stableLocal(program, function,
                    variable, registerMap, monitor);
                List<LocationRange> ranges = locationRanges(symbol, storage, stackDepths,
                    registerMap, rebaseDelta, variable.getSource());
                variableLocations.add(new VariableLocation(symbol.name(), address,
                    localName, VariableKind.LOCAL, variable.getLength(), ranges));
                if (storage instanceof UnavailableStorage unavailable) {
                    diagnostic.accept("Omitted location for " + symbol.name() + "::" +
                        localName + ": " + unavailable.diagnostic());
                }
            }
            signatures.add(new ProgramTypeModel.FunctionSignature(symbol.name(), address,
                returnType, parameters, locals, function.hasVarArgs(), function.hasNoReturn(),
                nonNull(function.getCallingConventionName()),
                function.getSignatureSource().name()));
        }
        for (FunctionSymbol missing : selected.values()) {
            diagnostic.accept("No Ghidra signature found for exported function " +
                missing.name());
        }
        List<ProgramTypeModel.GlobalVariable> globals = new ArrayList<>();
        SymbolIterator symbols = program.getSymbolTable().getAllSymbols(true);
        while (symbols.hasNext()) {
            monitor.checkCancelled();
            Symbol symbol = symbols.next();
            MemoryBlock block = program.getMemory().getBlock(symbol.getAddress());
            if (symbol.getSymbolType() != SymbolType.LABEL || !symbol.isPrimary() ||
                    symbol.isExternal() || symbol.getSource() == SourceType.DEFAULT ||
                    !symbol.getAddress().isMemoryAddress() || block == null ||
                    !block.isLoaded()) {
                continue;
            }
            Data data = program.getListing().getDataAt(symbol.getAddress());
            if (data == null || !data.isDefined() || data.getLength() <= 0) {
                continue;
            }
            long address;
            try {
                address = AddressNormalizer.toElfAddress(
                    symbol.getAddress().getOffset(), rebaseDelta);
            }
            catch (ArithmeticException overflow) {
                diagnostic.accept("Skipped untranslatable global " + symbol.getName());
                continue;
            }
            if (address < 0) {
                diagnostic.accept("Skipped unsupported global address " + symbol.getName());
                continue;
            }
            globals.add(new ProgramTypeModel.GlobalVariable(symbol.getName(), address,
                data.getLength(), extractor.reserve(data.getDataType()), false,
                symbol.getSource().name(),
                namespacePath(symbol.getParentNamespace())));
        }
        List<String> externalLibraries = new ArrayList<>(List.of(
            program.getExternalManager().getExternalLibraryNames()));
        externalLibraries.sort(String::compareTo);
        for (String library : externalLibraries) {
            ExternalLocationIterator locations =
                program.getExternalManager().getExternalLocations(library);
            while (locations.hasNext()) {
                monitor.checkCancelled();
                ExternalLocation location = locations.next();
                DataType type = location.getDataType();
                String name = location.getLabel();
                if (location.isFunction() || location.getSource() == SourceType.DEFAULT ||
                        name == null || name.isBlank() || type == null || type.getLength() <= 0) {
                    continue;
                }
                globals.add(new ProgramTypeModel.GlobalVariable(name, 0, type.getLength(),
                    extractor.reserve(type), true, location.getSource().name()));
            }
        }
        extractor.drain(monitor);
        return new ProgramTypeModel(new TypeGraph(new ArrayList<>(extractor.nodes.values())),
            signatures, globals, new VariableStorageModel(variableLocations));
    }

    private static List<String> namespacePath(Namespace namespace) {
        List<String> reversed = new ArrayList<>();
        for (Namespace current = namespace; current != null && !current.isGlobal();
                current = current.getParentNamespace()) {
            if (current.getType() != Namespace.Type.NAMESPACE) {
                return List.of();
            }
            reversed.add(current.getName());
        }
        java.util.Collections.reverse(reversed);
        return List.copyOf(reversed);
    }

    private static Evidence evidence(SourceType source, Storage storage) {
        Confidence confidence = switch (source) {
            case USER_DEFINED -> Confidence.USER_DEFINED;
            case IMPORTED -> Confidence.IMPORTED;
            case AI -> Confidence.DECOMPILER;
            case ANALYSIS, DEFAULT -> Confidence.ANALYSIS;
        };
        String suffix = storage instanceof RegisterRelativeStorage
                ? "; translated from Ghidra stack coordinates using analyzed " +
                    "instruction-level stack-pointer depth"
            : storage instanceof RegisterStorage
                ? "; register remains unmodified and function contains no calls"
                : "";
        return new Evidence(confidence, "Ghidra listing variable storage (" + source + ")" +
            suffix);
    }

    private static List<LocationRange> locationRanges(FunctionSymbol symbol,
            Storage storage, GhidraVariableStorage.StackDepthProfile stackDepths,
            TargetRegisterMap registerMap, long rebaseDelta, SourceType source) {
        if (!(storage instanceof StackStorage stack)) {
            return symbol.ranges().stream()
                .map(range -> new LocationRange(range.address(), range.endExclusive(),
                    storage, evidence(source, storage)))
                .toList();
        }
        List<LocationRange> result = new ArrayList<>();
        for (GhidraVariableStorage.StorageInterval interval :
                GhidraVariableStorage.stackIntervals(stackDepths, stack, registerMap)) {
            long start;
            long end;
            try {
                start = AddressNormalizer.toElfAddress(interval.start(), rebaseDelta);
                end = AddressNormalizer.toElfAddress(interval.end(), rebaseDelta);
            }
            catch (ArithmeticException overflow) {
                continue;
            }
            if (start >= 0 && end > start) {
                result.add(new LocationRange(start, end, interval.storage(),
                    evidence(source, interval.storage())));
            }
        }
        if (!result.isEmpty()) {
            return List.copyOf(result);
        }
        Storage unavailable = new UnavailableStorage(OmissionReason.UNKNOWN_LIFETIME,
            "no instruction has a defensible stack-pointer depth");
        return symbol.ranges().stream()
            .map(range -> new LocationRange(range.address(), range.endExclusive(),
                unavailable, evidence(source, unavailable)))
            .toList();
    }

    private static String safeParameterName(Parameter parameter) {
        String name = parameter.getName();
        return name == null ? "" : name;
    }

    private static String nonNull(String value) {
        return value == null ? "" : value;
    }

    private static final class Extractor {
        private final Consumer<String> diagnostic;
        private final IdentityHashMap<DataType, String> keys = new IdentityHashMap<>();
        private final Map<String, DataType> owners = new LinkedHashMap<>();
        private final Map<String, TypeNode> nodes = new LinkedHashMap<>();
        private final ArrayDeque<DataType> pending = new ArrayDeque<>();

        Extractor(Consumer<String> diagnostic) {
            this.diagnostic = diagnostic;
        }

        TypeRef reserve(DataType type) {
            if (type == null) {
                type = DataType.VOID;
            }
            String existing = keys.get(type);
            if (existing != null) {
                return new TypeRef(existing);
            }
            String key = uniqueKey(type);
            keys.put(type, key);
            owners.putIfAbsent(key, type);
            pending.addLast(type);
            return new TypeRef(key);
        }

        void drain(TaskMonitor monitor) throws CancelledException {
            while (!pending.isEmpty()) {
                monitor.checkCancelled();
                DataType type = pending.removeFirst();
                String key = keys.get(type);
                if (!nodes.containsKey(key)) {
                    nodes.put(key, convert(key, type));
                }
            }
        }

        private String uniqueKey(DataType type) {
            String base = stableKey(type);
            DataType owner = owners.get(base);
            if (owner == null || owner.isEquivalent(type)) {
                if (owner != null) {
                    keys.put(type, base);
                }
                return base;
            }
            long managerId = type.getDataTypeManager() == null ? -1 :
                type.getDataTypeManager().getID(type);
            String qualified = base + ":manager-id:" + Long.toUnsignedString(managerId, 16);
            DataType qualifiedOwner = owners.get(qualified);
            if (qualifiedOwner != null && !qualifiedOwner.isEquivalent(type)) {
                throw new IllegalStateException(
                    "cannot deterministically distinguish Ghidra type " + type.getPathName());
            }
            return qualified;
        }

        private TypeNode convert(String key, DataType type) {
            String name = displayName(type);
            if (VoidDataType.isVoidDataType(type)) {
                return new VoidType(key);
            }
            if (type instanceof BooleanDataType) {
                return new BaseType(key, name, positiveSize(type), BaseEncoding.BOOLEAN);
            }
            if (type instanceof CharDataType integer) {
                return new BaseType(key, name, positiveSize(type), integer.isSigned()
                    ? BaseEncoding.SIGNED_CHAR : BaseEncoding.UNSIGNED_CHAR);
            }
            if (type instanceof WideCharDataType || type instanceof WideChar16DataType ||
                    type instanceof WideChar32DataType) {
                return new BaseType(key, name, positiveSize(type), BaseEncoding.UTF);
            }
            if (type instanceof AbstractIntegerDataType integer) {
                return new BaseType(key, name, positiveSize(type), integer.isSigned()
                    ? BaseEncoding.SIGNED : BaseEncoding.UNSIGNED);
            }
            if (type instanceof AbstractFloatDataType) {
                return new BaseType(key, name, positiveSize(type), BaseEncoding.FLOAT);
            }
            if (type instanceof Pointer pointer) {
                return new IndirectionType(key, name, positiveSize(type),
                    IndirectionKind.POINTER, reserve(pointer.getDataType()));
            }
            if (type instanceof Array array) {
                return new ArrayType(key, name, nonNegativeSize(type),
                    reserve(array.getDataType()), array.getNumElements());
            }
            if (type instanceof TypeDef typedef) {
                return new TypedefType(key, name, nonNegativeSize(type),
                    reserve(typedef.getDataType()));
            }
            if (type instanceof Enum enumeration) {
                List<Enumerator> values = new ArrayList<>();
                for (String valueName : enumeration.getNames()) {
                    values.add(new Enumerator(valueName, enumeration.getValue(valueName)));
                }
                values.sort(Comparator.comparingLong(Enumerator::value)
                    .thenComparing(Enumerator::name));
                return new EnumType(key, name, positiveSize(type), enumeration.isSigned(), values);
            }
            if (type instanceof Structure structure) {
                return aggregate(key, name, structure, AggregateKind.STRUCTURE);
            }
            if (type instanceof Union union) {
                return aggregate(key, name, union, AggregateKind.UNION);
            }
            if (type instanceof FunctionDefinition function) {
                List<TypeGraph.Parameter> parameters = new ArrayList<>();
                for (ParameterDefinition parameter : function.getArguments()) {
                    String parameterName = parameter.getName();
                    parameters.add(new TypeGraph.Parameter(
                        parameterName == null ? "" : parameterName,
                        reserve(parameter.getDataType()), false));
                }
                return new SubroutineType(key, name, 0, reserve(function.getReturnType()),
                    parameters, function.hasVarArgs());
            }
            String reason = type instanceof Dynamic ? "dynamic-size Ghidra type" :
                Undefined.isUndefined(type) ? "undefined Ghidra type" :
                "unsupported Ghidra type class " + type.getClass().getName();
            diagnostic.accept("Type " + type.getPathName() + " retained as opaque: " + reason);
            return new OpaqueType(key, name, nonNegativeSize(type), reason);
        }

        private AggregateType aggregate(String key, String name, Composite composite,
                AggregateKind kind) {
            List<Member> members = new ArrayList<>();
            for (DataTypeComponent component : composite.getDefinedComponents()) {
                DataType memberType = component.getDataType();
                int bitSize = 0;
                int storageBitOffset = 0;
                if (memberType instanceof BitFieldDataType bitField) {
                    memberType = bitField.getBaseDataType();
                    bitSize = bitField.getBitSize();
                    storageBitOffset = bitField.getBitOffset();
                }
                String fieldName = component.getFieldName();
                if (fieldName == null || fieldName.isBlank()) {
                    fieldName = component.getDefaultFieldName();
                }
                members.add(new Member(fieldName, reserve(memberType), component.getOffset(),
                    bitSize, storageBitOffset));
            }
            return new AggregateType(key, name, nonNegativeSize(composite), kind, members);
        }

        private static String stableKey(DataType type) {
            UniversalID id = type.getUniversalID();
            if (id != null) {
                return "uid:" + Long.toUnsignedString(id.getValue(), 16);
            }
            return "type:" + type.getClass().getName() + ":" + type.getPathName() +
                ":" + type.getLength();
        }

        private static String displayName(DataType type) {
            String name = type.getDisplayName();
            return name == null || name.isBlank() ? type.getClass().getSimpleName() : name;
        }

        private static long positiveSize(DataType type) {
            if (type.getLength() <= 0) {
                throw new IllegalArgumentException("type has no positive size: " +
                    type.getPathName());
            }
            return type.getLength();
        }

        private static long nonNegativeSize(DataType type) {
            return Math.max(0, type.getLength());
        }
    }
}
