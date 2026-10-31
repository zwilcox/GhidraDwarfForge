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
import ghidra.program.model.data.DefaultDataType;
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
import ghidra.program.model.listing.AutoParameterType;
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
import ghidradwarfforge.locations.VariableStorageModel.CompositeStorage;
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
        return extract(program, exportedFunctions, targetName, rebaseDelta, monitor,
            diagnostic, Map.of());
    }

    /** Optional scalar return evidence from the same successful decompiler pass. */
    public static ProgramTypeModel extract(Program program,
            List<FunctionSymbol> exportedFunctions, String targetName, long rebaseDelta,
            TaskMonitor monitor, Consumer<String> diagnostic,
            Map<Long, DataType> recoveredReturns) throws CancelledException {
        return extract(program, exportedFunctions, targetName, rebaseDelta, monitor,
            diagnostic, recoveredReturns, Map.of());
    }

    public static ProgramTypeModel extract(Program program,
            List<FunctionSymbol> exportedFunctions, String targetName, long rebaseDelta,
            TaskMonitor monitor, Consumer<String> diagnostic,
            Map<Long, DataType> recoveredReturns,
            Map<Long, GhidraSyntheticSource.ParameterRecovery> recoveredParameters)
            throws CancelledException {
        return extract(program, exportedFunctions, TargetRegisterMap.forTarget(targetName),
            rebaseDelta, monitor, diagnostic, recoveredReturns, recoveredParameters);
    }

    public static ProgramTypeModel extract(Program program,
            List<FunctionSymbol> exportedFunctions, TargetRegisterMap registerMap, long rebaseDelta,
            TaskMonitor monitor, Consumer<String> diagnostic,
            Map<Long, DataType> recoveredReturns,
            Map<Long, GhidraSyntheticSource.ParameterRecovery> recoveredParameters)
            throws CancelledException {
        Extractor extractor = new Extractor(program, diagnostic);
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
        var lexicalScopes = new ArrayList<ghidradwarfforge.types.LexicalScopeModel>();
        List<ProgramTypeModel.FunctionDeclaration> declarations = new ArrayList<>();
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
            // Resolve instruction-level stack depths only when an exported
            // location needs them, then share that profile within this function.
            GhidraVariableStorage.StackDepthProfile stackDepths = null;
            // The effective ABI return may be a hidden pointer (or void).
            // Preserve the curated signature independently of that carrier.
            DataType formalReturn = function.getReturn().getFormalDataType();
            DataType recoveredReturn = recoveredReturns.get(address);
            if (acceptRecoveredReturn(function, recoveredReturn)) {
                formalReturn = recoveredReturn;
                diagnostic.accept("Using decompiler-recovered scalar return for " +
                    symbol.name() + ": " + recoveredReturn.getName() +
                    "; saved DEFAULT undefined signature remains unchanged");
            }
            TypeRef returnType = extractor.reserve(formalReturn);
            List<TypeGraph.Parameter> parameters = new ArrayList<>();
            for (Parameter parameter : function.getParameters()) {
                DataType formalType = parameter.getFormalDataType();
                int logicalLength = formalType == null ? parameter.getLength()
                    : formalType.getLength();
                String parameterName = safeParameterName(parameter);
                parameters.add(new TypeGraph.Parameter(parameterName,
                    extractor.reserve(formalType), parameter.isAutoParameter(),
                    parameter.getAutoParameterType() == AutoParameterType.RETURN_STORAGE_PTR,
                    parameter.getAutoParameterType() == AutoParameterType.THIS));
                if (!parameterName.isBlank() && logicalLength > 0) {
                    Storage storage = GhidraVariableStorage.stableParameter(program, function,
                        parameter, registerMap, monitor);
                    var prefix = GhidraVariableStorage.parameterPrefix(program, function,
                        parameter, registerMap, storage, monitor);
                    if (prefix.isEmpty() && storage instanceof UnavailableStorage) {
                        prefix = StackValueFlow.prove(program, function, parameter, registerMap, monitor);
                    }
                    if (storage instanceof UnavailableStorage && parameter.getVariableStorage() != null &&
                            parameter.getVariableStorage().getVarnodeCount() > 1) {
                        var pieces = CompositeValueFlow.prove(program, function, parameter, registerMap, monitor);
                        prefix = prefix.isEmpty() ? pieces : StackValueFlow.extendUnavailable(prefix, pieces);
                    }
                    if (prefix.isEmpty() && storage instanceof StackStorage && stackDepths == null) {
                        stackDepths = GhidraVariableStorage.stackDepthProfile(program, function, monitor);
                    }
                    List<LocationRange> ranges = prefix.isEmpty()
                        ? locationRanges(symbol, storage, stackDepths, registerMap, rebaseDelta,
                            parameter.getSource())
                        : parameterPrefixRanges(prefix, rebaseDelta, parameter.getSource());
                    variableLocations.add(new VariableLocation(symbol.name(), address,
                        parameterName, VariableKind.PARAMETER, logicalLength, ranges));
                    if (storage instanceof UnavailableStorage unavailable) {
                        diagnostic.accept((prefix.isEmpty() ? "Omitted location for " :
                            GhidraVariableStorage.hasStackPiece(parameter.getVariableStorage())
                                ? "Limited location to proven incoming mixed-storage lifetime for " :
                            prefix.stream().anyMatch(interval -> interval.storage() instanceof
                                ghidradwarfforge.locations.VariableStorageModel.RegisterRelativeStorage)
                                ? "Limited location to proven stack-spill lifetime for " :
                            prefix.stream().filter(interval -> interval.storage().available())
                                .count() > 1 ? "Limited location to proven register-copy lifetime for " :
                                "Limited location to proven incoming-register lifetime for ") +
                            symbol.name() + "::" + parameterName + ": " +
                            unavailable.diagnostic());
                    }
                }
            }
            List<ProgramTypeModel.LocalVariable> locals = new ArrayList<>();
            var recovery = recoveredParameters.get(address);
            if (recovery != null && acceptRecoveredParameters(function)) {
                java.util.Set<String> names = new java.util.HashSet<>();
                for (Variable local : function.getLocalVariables()) {
                    names.add(local.getName());
                }
                String omission = recovery.omission();
                for (var parameter : recovery.parameters()) {
                    if (!names.add(parameter.name()) ||
                            !GhidraSyntheticSource.supportedParameterType(parameter.type())) {
                        omission = "unresolved type or conflicting listing-local name";
                        break;
                    }
                }
                if (omission != null) {
                    diagnostic.accept("Omitted decompiler parameter recovery for " + symbol.name() + ": " + omission);
                }
                else {
                    for (var parameter : recovery.parameters()) {
                        parameters.add(new TypeGraph.Parameter(parameter.name(),
                            extractor.reserve(parameter.type()), false));
                        var storage = new UnavailableStorage(OmissionReason.UNKNOWN_LIFETIME,
                            "decompiler name/type evidence has no validated variable lifetime");
                        var evidence = new Evidence(Confidence.DECOMPILER,
                            "Ghidra decompiler parameter metadata; no listing storage or inferred location emitted");
                        variableLocations.add(new VariableLocation(symbol.name(), address,
                            parameter.name(), VariableKind.PARAMETER, parameter.type().getLength(),
                            symbol.ranges().stream().map(range -> new LocationRange(
                                range.address(), range.endExclusive(), storage, evidence)).toList()));
                    }
                    diagnostic.accept("Using decompiler-recovered parameter names/types for " +
                        symbol.name() + "; locations omitted and DEFAULT prototype remains unspecified");
                }
            }
            Map<Variable, GhidraLocalMappings.Group> mergedOwners = new HashMap<>();
            for (var group : GhidraLocalMappings.extract(program, function, monitor, diagnostic)) {
                for (var mapping : group.mappings()) mergedOwners.put(mapping.variable(), group);
                diagnostic.accept("Saved Ghidra merged-local identity for " + symbol.name() + "::" +
                    group.canonical().getName() + ": " + group.mappings().stream().map(mapping ->
                        mapping.variable().getName() + " at " + mapping.definition() + " in " +
                        (mapping.register() == null ? mapping.variable().getVariableStorage().toString() :
                            mapping.register().getName())).toList() + "; analyst mappings, not original compiler facts");
            }
            for (Variable variable : function.getLocalVariables()) {
                monitor.checkCancelled();
                var merged = mergedOwners.get(variable);
                if (merged != null && merged.canonical() != variable) continue;
                String localName = variable.getName();
                if (localName == null || localName.isBlank() || variable.getLength() <= 0) {
                    diagnostic.accept("Skipped unnamed or zero-size local in " + symbol.name());
                    continue;
                }
                locals.add(new ProgramTypeModel.LocalVariable(localName,
                    variable.getLength(), extractor.reserve(variable.getDataType()),
                    variable.getFirstUseOffset(), variable.hasAssignedStorage(),
                    variable.getSource().name()));
                Storage storage = merged == null ? GhidraVariableStorage.stableLocal(program, function,
                    variable, registerMap, monitor) : new UnavailableStorage(OmissionReason.UNKNOWN_LIFETIME,
                        "saved merged local requires proof of its latest definition and storage");
                var linearPrefix = merged == null ? GhidraVariableStorage.localPrefix(program, function, variable,
                    registerMap, storage, monitor) : List.<GhidraVariableStorage.StorageInterval>of();
                var controlFlow = merged != null ? MergedLocalLifetime.prove(program, function, merged, registerMap, monitor)
                    : linearPrefix.isEmpty()
                        ? RegisterDefinitionFlow.prove(program, function, variable, registerMap, storage, monitor)
                        : List.<GhidraVariableStorage.StorageInterval>of();
                var stackLocal = merged == null && linearPrefix.isEmpty() && controlFlow.isEmpty()
                    ? StackLocalLifetime.prove(program, function, variable, registerMap, storage, monitor)
                    : List.<GhidraVariableStorage.StorageInterval>of();
                var prefix = !stackLocal.isEmpty() ? stackLocal : controlFlow.isEmpty() ? linearPrefix : controlFlow;
                String lifetimeEvidence = !stackLocal.isEmpty()
                    ? "Saved function-owned stack local; recorded start matches a completed full-width stack STORE; " +
                        "subsequent transfers preserve the current value; overlapping assignments, unknown aliases " +
                        "and later saved slot owners retire all old copies; no original lexical scope inferred"
                    : merged != null
                    ? "Saved Ghidra canonical merged-local identity; all explicit full-width definitions " +
                        "checked against raw instructions; latest assignment invalidates previous carriers; " +
                        "all incoming paths must agree on physical storage; no original lexical scope inferred"
                    : controlFlow.isEmpty()
                    ? "Curated Ghidra function-owned local; exact recorded register read or completed " +
                        "definition in a fully decoded straight-line leaf; unavailable " +
                        "before first use and after overwrite; no original lexical scope inferred"
                    : "Curated Ghidra function-owned local; recorded complete register definition " +
                        "and unchanged physical storage proven on every incoming path in a closed " +
                        "decoded control-flow graph; unproved joins and body holes have no location; " +
                        "no original lexical scope inferred";
                if (storage instanceof StackStorage && stackDepths == null) {
                    stackDepths = GhidraVariableStorage.stackDepthProfile(program, function, monitor);
                }
                List<LocationRange> ranges = prefix.isEmpty()
                    ? locationRanges(symbol, storage, stackDepths, registerMap, rebaseDelta, variable.getSource())
                    : prefix.stream().map(interval -> new LocationRange(
                        AddressNormalizer.toElfAddress(interval.start(), rebaseDelta),
                        AddressNormalizer.toElfAddress(interval.end(), rebaseDelta), interval.storage(),
                        new Evidence(evidence(variable.getSource(), interval.storage()).confidence(),
                            lifetimeEvidence)))
                        .toList();
                variableLocations.add(new VariableLocation(symbol.name(), address,
                    localName, VariableKind.LOCAL, variable.getLength(), ranges));
                if (storage instanceof UnavailableStorage unavailable) {
                    diagnostic.accept((prefix.isEmpty() ? "Omitted location for " :
                        !stackLocal.isEmpty() ? "Limited location to proven stack-local lifetime for " :
                        merged != null ? "Limited location to proven merged-local lifetime for " :
                        controlFlow.isEmpty() ? "Limited location to proven later-register-local lifetime for " :
                        "Limited location to proven control-flow-local lifetime for ") + symbol.name() + "::" +
                        localName + ": " + unavailable.diagnostic());
                }
            }
            var savedScopes = GhidraLexicalScopes.read(function, monitor, diagnostic);
            if (savedScopes.isPresent()) {
                var saved = savedScopes.get();
                boolean valid = saved.locals().stream().allMatch(binding ->
                    locals.stream().filter(local -> local.name().equals(binding.variable().getName()) &&
                        local.firstUseOffset() == binding.variable().getFirstUseOffset()).count() == 1);
                if (!valid) {
                    diagnostic.accept("Omitted saved lexical scopes for " + symbol.name() +
                        ": a bound local was skipped or coalesced during extraction");
                }
                else {
                    try {
                        var blocks = new ArrayList<ghidradwarfforge.types.LexicalScopeModel.Block>();
                        for (var block : saved.blocks()) {
                            monitor.checkCancelled();
                            var ranges = new ArrayList<ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange>();
                            for (var range : block.body().getAddressRanges()) {
                                monitor.checkCancelled();
                                long start = AddressNormalizer.toElfAddress(range.getMinAddress().getOffset(), rebaseDelta);
                                long end = Math.addExact(AddressNormalizer.toElfAddress(range.getMaxAddress().getOffset(), rebaseDelta), 1);
                                ranges.add(new ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange(start, Math.subtractExact(end, start)));
                            }
                            blocks.add(new ghidradwarfforge.types.LexicalScopeModel.Block(block.id(), block.parent(), ranges));
                        }
                        lexicalScopes.add(new ghidradwarfforge.types.LexicalScopeModel(address, symbol.ranges(), blocks,
                            saved.locals().stream().map(binding -> new ghidradwarfforge.types.LexicalScopeModel.Local(
                                binding.variable().getName(), binding.block(), binding.displayName())).toList(), saved.evidence()));
                        diagnostic.accept("Using explicitly saved lexical ownership for " + symbol.name() +
                            "; visibility does not establish variable storage; " + saved.evidence());
                    }
                    catch (ArithmeticException | IllegalArgumentException invalidScope) {
                        diagnostic.accept("Omitted saved lexical scopes for " + symbol.name() + ": " + invalidScope.getMessage());
                    }
                }
            }
            boolean nonDefaultConvention = nonDefaultCallingConvention(program, function);
            String callRestriction = GhidraCustomCallStorage.restriction(program, function, monitor);
            if (nonDefaultConvention) {
                diagnostic.accept("Debugger-injected calls disabled for " + symbol.name() +
                    ": selected Ghidra calling convention " + function.getCallingConventionName() +
                    " differs from the program default; no debugger ABI mapping is established");
            }
            else if (!callRestriction.isEmpty()) {
                diagnostic.accept("Debugger-injected calls disabled for " + symbol.name() + ": " + callRestriction);
            }
            signatures.add(new ProgramTypeModel.FunctionSignature(symbol.name(), address,
                returnType, parameters, locals, function.hasVarArgs(), function.hasNoReturn(),
                nonNull(function.getCallingConventionName()),
                function.getSignatureSource().name(), nonDefaultConvention, callRestriction));
        }
        for (FunctionSymbol missing : selected.values()) {
            diagnostic.accept("No Ghidra signature found for exported function " +
                missing.name());
        }
        List<ProgramTypeModel.GlobalVariable> globals = new ArrayList<>();
        List<ProgramTypeModel.FunctionStaticVariable> functionStatics = new ArrayList<>();
        java.util.Set<Long> functionOwners = signatures.stream()
            .map(ProgramTypeModel.FunctionSignature::address)
            .collect(java.util.stream.Collectors.toSet());
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
            if (symbol.getParentNamespace() instanceof Function owner) {
                long ownerAddress;
                try {
                    ownerAddress = AddressNormalizer.toElfAddress(
                        owner.getEntryPoint().getOffset(), rebaseDelta);
                }
                catch (ArithmeticException overflow) {
                    diagnostic.accept("Skipped function-owned static variable " +
                        symbol.getName(true) + "; untranslatable owner address");
                    continue;
                }
                if (!functionOwners.contains(ownerAddress)) {
                    diagnostic.accept("Skipped function-owned static variable " +
                        symbol.getName(true) + "; owning function was not exported");
                    continue;
                }
                functionStatics.add(new ProgramTypeModel.FunctionStaticVariable(
                    symbol.getName(), address, data.getLength(),
                    extractor.reserve(data.getDataType()), ownerAddress,
                    symbol.getSource().name()));
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
        FunctionIterator externals = program.getFunctionManager().getExternalFunctions();
        while (externals.hasNext()) {
            monitor.checkCancelled();
            Function external = externals.next();
            if (external.getSignatureSource() == SourceType.DEFAULT) {
                continue;
            }
            List<TypeGraph.Parameter> parameters = new ArrayList<>();
            for (Parameter parameter : external.getParameters()) {
                monitor.checkCancelled();
                parameters.add(new TypeGraph.Parameter(safeParameterName(parameter),
                    extractor.reserve(parameter.getFormalDataType()), parameter.isAutoParameter(),
                    parameter.getAutoParameterType() == AutoParameterType.RETURN_STORAGE_PTR,
                    parameter.getAutoParameterType() == AutoParameterType.THIS));
            }
            // An external-space placeholder is not an address in this image.
            // Preserve its persistent identity and full Ghidra display name only.
            boolean nonDefaultConvention = nonDefaultCallingConvention(program, external);
            String callRestriction = GhidraCustomCallStorage.restriction(program, external, monitor);
            if (nonDefaultConvention) {
                diagnostic.accept("Debugger-injected calls disabled for " + external.getName(true) +
                    ": selected Ghidra calling convention " + external.getCallingConventionName() +
                    " differs from the program default; no debugger ABI mapping is established");
            }
            else if (!callRestriction.isEmpty()) {
                diagnostic.accept("Debugger-injected calls disabled for " + external.getName(true) + ": " + callRestriction);
            }
            declarations.add(new ProgramTypeModel.FunctionDeclaration(
                "external:" + Long.toUnsignedString(external.getID()), external.getName(true),
                extractor.reserve(external.getReturn().getFormalDataType()), parameters,
                external.hasVarArgs(), external.hasNoReturn(),
                external.getCallingConventionName(), external.getSignatureSource().name(),
                nonDefaultConvention, callRestriction));
        }
        extractor.drain(monitor);
        return new ProgramTypeModel(new TypeGraph(new ArrayList<>(extractor.nodes.values())),
            signatures, globals, new VariableStorageModel(variableLocations), functionStatics,
            declarations, lexicalScopes);
    }

    static boolean acceptRecoveredReturn(Function function, DataType recovered) {
        return function.getSignatureSource() == SourceType.DEFAULT &&
            function.getReturn().getSource() == SourceType.DEFAULT &&
            !function.hasCustomVariableStorage() &&
            Undefined.isUndefined(function.getReturn().getFormalDataType()) &&
            recovered != null && !Undefined.isUndefined(recovered) &&
            recovered.getLength() > 0 &&
            (recovered instanceof AbstractIntegerDataType ||
                recovered instanceof AbstractFloatDataType || recovered instanceof BooleanDataType);
    }

    static boolean acceptRecoveredParameters(Function function) {
        return function.getSignatureSource() == SourceType.DEFAULT &&
            !function.hasCustomVariableStorage() && function.getParameterCount() == 0 &&
            !function.hasVarArgs();
    }

    /** Compare resolved models, not architecture-specific names or a raw default alias. */
    static boolean nonDefaultCallingConvention(Program program, Function function) {
        var selected = function.getCallingConvention();
        var fallback = program.getCompilerSpec().getDefaultCallingConvention();
        return selected != null && fallback != null &&
            !selected.getName().equals(fallback.getName());
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

    private static List<LocationRange> parameterPrefixRanges(
            List<GhidraVariableStorage.StorageInterval> intervals, long rebaseDelta,
            SourceType source) {
        boolean mixed = intervals.stream().anyMatch(interval ->
            interval.storage() instanceof CompositeStorage composite && composite.pieces().stream()
                .anyMatch(piece -> piece.storage() instanceof RegisterRelativeStorage));
        return intervals.stream().map(interval -> {
            var confidence = evidence(source, interval.storage()).confidence();
            Evidence evidence = new Evidence(confidence,
                "Ghidra listing parameter storage (" + source + "); fully decoded " +
                    (mixed ? "straight-line leaf with exact register/stack pieces and analyzed " +
                        "stack-pointer depth; bounded by the first possible memory or register write" :
                        "instruction path with incoming bits and completed exact-bit register " +
                        "copies, stack stores/reloads or inspected direct-leaf preservation, as applicable") + "; unproven intervals are unavailable");
            return new LocationRange(AddressNormalizer.toElfAddress(interval.start(), rebaseDelta),
                AddressNormalizer.toElfAddress(interval.end(), rebaseDelta),
                interval.storage(), evidence);
        }).toList();
    }

    private static String safeParameterName(Parameter parameter) {
        String name = parameter.getName();
        return name == null ? "" : name;
    }

    private static String nonNull(String value) {
        return value == null ? "" : value;
    }

    private static final class Extractor {
        private final Program program;
        private final Consumer<String> diagnostic;
        private final IdentityHashMap<DataType, String> keys = new IdentityHashMap<>();
        private final Map<String, DataType> owners = new LinkedHashMap<>();
        private final Map<String, TypeNode> nodes = new LinkedHashMap<>();
        private final ArrayDeque<DataType> pending = new ArrayDeque<>();

        Extractor(Program program, Consumer<String> diagnostic) {
            this.program = program;
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
                if (function.hasNoReturn()) {
                    diagnostic.accept("Function type " + type.getPathName() +
                        " no-return property omitted: DW_AT_noreturn describes subprograms; " +
                        "no validated subroutine-type mapping");
                }
                List<TypeGraph.Parameter> parameters = new ArrayList<>();
                for (ParameterDefinition parameter : function.getArguments()) {
                    String parameterName = parameter.getName();
                    parameters.add(new TypeGraph.Parameter(
                        parameterName == null ? "" : parameterName,
                        reserve(parameter.getDataType()), false));
                }
                String convention = function.getCallingConventionName();
                var selected = function.getCallingConvention();
                var fallback = program.getCompilerSpec().getDefaultCallingConvention();
                String restriction = selected == null || fallback == null ?
                    "function type has no resolved calling convention" :
                    selected.getName().equals(fallback.getName()) ? "" :
                    "function type calling convention " + selected.getName() +
                        " differs from the program default; no debugger ABI mapping";
                if (!restriction.isEmpty()) {
                    diagnostic.accept("Debugger-injected calls disabled for function type " + name + ": " + restriction);
                }
                return new SubroutineType(key, name, 0, reserve(function.getReturnType()),
                    parameters, function.hasVarArgs(), convention == null ? "" : convention, restriction);
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
                int storageByteSize = 0;
                if (memberType instanceof BitFieldDataType bitField) {
                    memberType = bitField.getBaseDataType();
                    bitSize = bitField.getBitSize();
                    if (bitSize == 0) {
                        // A zero-width bit field imposes alignment; it has no
                        // readable value. Subsequent component offsets retain
                        // its layout effect without inventing an ordinary member.
                        continue;
                    }
                    storageBitOffset = bitField.getBitOffset();
                    storageByteSize = bitField.getStorageSize();
                }
                String fieldName = component.getFieldName();
                if (fieldName == null || fieldName.isBlank()) {
                    fieldName = component.getDefaultFieldName();
                }
                members.add(new Member(fieldName, reserve(memberType), component.getOffset(),
                    bitSize, storageBitOffset, storageByteSize));
            }
            return new AggregateType(key, name, nonNegativeSize(composite), kind, members);
        }

        private static String stableKey(DataType type) {
            // Ghidra's generic undefined singleton inherits a process-local ID,
            // unlike persisted analyst/imported types. Use its existing built-in
            // fallback identity so saving and reopening cannot reorder the graph.
            UniversalID id = type.getClass() == DefaultDataType.class ? null :
                type.getUniversalID();
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
