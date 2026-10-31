package ghidradwarfforge;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.AbstractFloatDataType;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.pcode.FunctionPrototype;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.source.SyntheticSourceFile;
import ghidradwarfforge.source.SyntheticSourceFile.FunctionText;
import ghidradwarfforge.source.SyntheticSourceFile.RelativeLine;

/** Decompiles the already-selected symbol functions with per-function isolation. */
public final class GhidraSyntheticSource {
    private static final int DECOMPILE_TIMEOUT_SECONDS = 60;

    /** Return evidence belongs to this pass; it never changes the saved program. */
    public record Decompilation(SyntheticSourceFile source,
            Map<Long, DataType> recoveredReturns,
            Map<Long, ParameterRecovery> recoveredParameters,
            Map<Long, GhidraStaticRecovery.Result> recoveredStatics) {
        public Decompilation {
            Objects.requireNonNull(source, "synthetic source");
            recoveredReturns = Map.copyOf(recoveredReturns);
            recoveredParameters = Map.copyOf(recoveredParameters);
            recoveredStatics = Map.copyOf(recoveredStatics);
        }

        public Decompilation(SyntheticSourceFile source, Map<Long, DataType> recoveredReturns,
                Map<Long, ParameterRecovery> recoveredParameters) {
            this(source, recoveredReturns, recoveredParameters, Map.of());
        }

        public Decompilation(SyntheticSourceFile source, Map<Long, DataType> recoveredReturns) {
            this(source, recoveredReturns, Map.of());
        }
    }

    public record RecoveredParameter(String name, DataType type) {
        public RecoveredParameter {
            if (name == null || name.isBlank() || type == null) {
                throw new IllegalArgumentException("recovered parameter name/type required");
            }
        }
    }

    /** Either an ordered complete recovered list, or a diagnostic without a partial list. */
    public record ParameterRecovery(List<RecoveredParameter> parameters, String omission) {
        public ParameterRecovery {
            parameters = List.copyOf(parameters);
            if (parameters.isEmpty() ? omission == null || omission.isBlank() : omission != null) {
                throw new IllegalArgumentException("parameter list or omission required exclusively");
            }
        }
    }

    @FunctionalInterface
    public interface DecompileOperation {
        DecompileResults decompile(DecompInterface decompiler, Function function,
                int timeoutSeconds, TaskMonitor monitor);
    }

    private GhidraSyntheticSource() {
    }

    public static SyntheticSourceFile decompile(Program program,
            List<FunctionSymbol> exportedFunctions, long rebaseDelta, TaskMonitor monitor)
            throws CancelledException {
        return decompileDetailed(program, exportedFunctions, rebaseDelta, monitor).source();
    }

    public static Decompilation decompileDetailed(Program program,
            List<FunctionSymbol> exportedFunctions, long rebaseDelta, TaskMonitor monitor)
            throws CancelledException {
        return decompileDetailed(program, exportedFunctions, rebaseDelta, monitor,
            (decompiler, function, timeoutSeconds, taskMonitor) ->
                decompiler.decompileFunction(function, timeoutSeconds, taskMonitor));
    }

    /** Allows integration callers to wrap one decompilation attempt deterministically. */
    public static SyntheticSourceFile decompile(Program program,
            List<FunctionSymbol> exportedFunctions, long rebaseDelta, TaskMonitor monitor,
            DecompileOperation operation) throws CancelledException {
        return decompileDetailed(program, exportedFunctions, rebaseDelta, monitor,
            operation).source();
    }

    public static Decompilation decompileDetailed(Program program,
            List<FunctionSymbol> exportedFunctions, long rebaseDelta, TaskMonitor monitor,
            DecompileOperation operation) throws CancelledException {
        Objects.requireNonNull(operation, "decompile operation");
        Map<Long, DataType> recoveredReturns = new HashMap<>();
        Map<Long, ParameterRecovery> recoveredParameters = new HashMap<>();
        Map<Long, GhidraStaticRecovery.Result> recoveredStatics = new HashMap<>();
        Map<Long, FunctionSymbol> selected = new HashMap<>();
        for (FunctionSymbol symbol : exportedFunctions) {
            selected.put(symbol.address(), symbol);
        }
        List<FunctionText> texts = new ArrayList<>();
        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.setOptions(new DecompileOptions());
            decompiler.toggleCCode(true);
            decompiler.toggleSyntaxTree(true);
            if (!decompiler.openProgram(program)) {
                throw new IllegalStateException(
                    "decompiler could not open program: " + decompiler.getLastMessage());
            }
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
                if (function.isThunk()) {
                    // Ghidra may substitute the destination's body when decompiling
                    // a thunk. That text is not source evidence for this memory body.
                    texts.add(FunctionText.omitted(symbol.name(), symbol.address(),
                        "curated thunk; destination decompilation is not source for this body"));
                    continue;
                }
                monitor.setMessage("Decompiling " + symbol.name());
                try {
                    DecompileResults result = operation.decompile(decompiler, function,
                        DECOMPILE_TIMEOUT_SECONDS, monitor);
                    monitor.checkCancelled();
                    if (result != null && result.decompileCompleted() &&
                            result.getDecompiledFunction() != null) {
                        String c = result.getDecompiledFunction().getC();
                        DataType recovered = result.getHighFunction() == null ? null :
                            result.getHighFunction().getFunctionPrototype().getReturnType();
                        boolean acceptReturn = GhidraTypeGraph.acceptRecoveredReturn(function,
                            recovered);
                        ParameterRecovery parameters = result.getHighFunction() == null ||
                                !GhidraTypeGraph.acceptRecoveredParameters(function) ? null :
                            recoverParameters(result.getHighFunction().getFunctionPrototype());
                        var statics = GhidraStaticRecovery.recover(result.getHighFunction(), monitor);
                        texts.add(new FunctionText(symbol.name(), symbol.address(),
                            c, null, mapTokens(result.getCCodeMarkup(), c, symbol,
                                rebaseDelta)));
                        if (acceptReturn) {
                            recoveredReturns.put(symbol.address(), recovered);
                        }
                        if (parameters != null) {
                            recoveredParameters.put(symbol.address(), parameters);
                        }
                        recoveredStatics.put(symbol.address(), statics);
                    }
                    else {
                        String diagnostic = result == null ? "no decompiler result" :
                            result.getErrorMessage();
                        texts.add(new FunctionText(symbol.name(), symbol.address(), null,
                            diagnostic == null || diagnostic.isBlank()
                                    ? "decompilation did not complete" : diagnostic));
                        decompiler.resetDecompiler();
                    }
                }
                catch (RuntimeException failure) {
                    texts.add(new FunctionText(symbol.name(), symbol.address(), null,
                        failure.getClass().getSimpleName() + ": " + failure.getMessage()));
                    decompiler.resetDecompiler();
                }
            }
        }
        finally {
            decompiler.dispose();
        }
        monitor.checkCancelled();
        for (FunctionSymbol missing : selected.values()) {
            texts.add(new FunctionText(missing.name(), missing.address(), null,
                "selected function was not found during the decompiler pass"));
        }
        return new Decompilation(SyntheticSourceFile.build(program.getName(),
            program.getLanguageID().toString(), texts), recoveredReturns, recoveredParameters, recoveredStatics);
    }

    private static ParameterRecovery recoverParameters(FunctionPrototype prototype) {
        if (prototype.getNumParams() == 0) {
            return null;
        }
        if (prototype.isVarArg()) {
            return new ParameterRecovery(List.of(), "inferred variadic signature is outside the supported recovery policy");
        }
        List<RecoveredParameter> parameters = new ArrayList<>();
        java.util.Set<String> names = new java.util.HashSet<>();
        for (int index = 0; index < prototype.getNumParams(); index++) {
            var parameter = prototype.getParam(index);
            if (parameter == null || parameter.isThisPointer() || parameter.isHiddenReturn()) {
                return new ParameterRecovery(List.of(), "missing or implicit parameter at position " + index);
            }
            String name = parameter.getName();
            if (name == null || name.isBlank() || !names.add(name) ||
                    !supportedParameterType(parameter.getDataType())) {
                return new ParameterRecovery(List.of(), "unresolved type or ambiguous name at position " + index);
            }
            parameters.add(new RecoveredParameter(name, parameter.getDataType()));
        }
        return new ParameterRecovery(parameters, null);
    }

    static boolean supportedParameterType(DataType type) {
        return type != null && !Undefined.isUndefined(type) &&
            (type instanceof AbstractIntegerDataType || type instanceof AbstractFloatDataType ||
                type instanceof BooleanDataType || type instanceof Pointer) && type.getLength() > 0;
    }

    private static List<RelativeLine> mapTokens(ClangTokenGroup markup, String c,
            FunctionSymbol function, long rebaseDelta) {
        if (markup == null) {
            return List.of();
        }
        Map<Integer, List<Long>> lines = new TreeMap<>();
        int cLineCount = c.split("\\n", -1).length;
        for (ClangLine clangLine : DecompilerUtils.toLines(markup)) {
            int line = clangLine.getLineNumber();
            if (line < 1 || line > cLineCount) {
                continue;
            }
            for (ClangToken token : clangLine.getAllTokens()) {
                String text = token.getText();
                if (text == null || text.isBlank() ||
                        token.getSyntaxType() == ClangToken.COMMENT_COLOR) {
                    continue;
                }
                Address evidence = token.getPcodeOp() == null ? token.getMinAddress()
                        : token.getPcodeOp().getSeqnum().getTarget();
                if (evidence == null || !evidence.isMemoryAddress()) {
                    continue;
                }
                try {
                    long address = AddressNormalizer.toElfAddress(
                        evidence.getOffset(), rebaseDelta);
                    if (function.contains(address)) {
                        lines.computeIfAbsent(line, ignored -> new ArrayList<>()).add(address);
                    }
                }
                catch (ArithmeticException overflow) {
                    // Evidence outside the supported signed-address model is omitted.
                }
            }
        }
        return lines.entrySet().stream()
            .map(entry -> new RelativeLine(entry.getKey(), entry.getValue())).toList();
    }
}
