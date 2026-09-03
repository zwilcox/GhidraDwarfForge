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
        return decompile(program, exportedFunctions, rebaseDelta, monitor,
            (decompiler, function, timeoutSeconds, taskMonitor) ->
                decompiler.decompileFunction(function, timeoutSeconds, taskMonitor));
    }

    /** Allows integration callers to wrap one decompilation attempt deterministically. */
    public static SyntheticSourceFile decompile(Program program,
            List<FunctionSymbol> exportedFunctions, long rebaseDelta, TaskMonitor monitor,
            DecompileOperation operation) throws CancelledException {
        Objects.requireNonNull(operation, "decompile operation");
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
                monitor.setMessage("Decompiling " + symbol.name());
                try {
                    DecompileResults result = operation.decompile(decompiler, function,
                        DECOMPILE_TIMEOUT_SECONDS, monitor);
                    monitor.checkCancelled();
                    if (result != null && result.decompileCompleted() &&
                            result.getDecompiledFunction() != null) {
                        String c = result.getDecompiledFunction().getC();
                        texts.add(new FunctionText(symbol.name(), symbol.address(),
                            c, null, mapTokens(result.getCCodeMarkup(), c, symbol,
                                rebaseDelta)));
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
        return SyntheticSourceFile.build(program.getName(), program.getLanguageID().toString(),
            texts);
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
