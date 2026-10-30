package ghidradwarfforge;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.function.Consumer;

import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange;

/** Extracts the narrow, evidence-backed function model used by the P0 milestone. */
public final class GhidraFunctionSymbols {
    public enum SkipReason {
        EXTERNAL_IMPORT,
        THUNK,
        BODYLESS,
        NON_MEMORY,
        ENTRY_OUTSIDE_BODY,
        UNSUPPORTED_RANGE,
        UNTRANSLATABLE_ADDRESS
    }

    public record SkippedFunction(String name, SkipReason reason) {
        public SkippedFunction {
            if (name == null || name.isBlank() || reason == null) {
                throw new IllegalArgumentException("invalid skipped function");
            }
        }
    }

    public record ExtractionResult(List<FunctionSymbol> functions,
            List<SkippedFunction> skippedFunctions) {
        public ExtractionResult {
            functions = List.copyOf(functions);
            skippedFunctions = skippedFunctions.stream()
                .sorted(Comparator.comparing(SkippedFunction::name)
                    .thenComparing(skipped -> skipped.reason().name()))
                .toList();
        }
    }

    private GhidraFunctionSymbols() {
    }

    public static List<FunctionSymbol> extract(Program program, TaskMonitor monitor,
            Consumer<String> diagnostic, long rebaseDelta) throws CancelledException {
        return extractDetailed(program, monitor, diagnostic, rebaseDelta).functions();
    }

    public static ExtractionResult extractDetailed(Program program, TaskMonitor monitor,
            Consumer<String> diagnostic, long rebaseDelta) throws CancelledException {
        List<FunctionSymbol> result = new ArrayList<>();
        List<SkippedFunction> skipped = new ArrayList<>();
        FunctionIterator functions = program.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            monitor.checkCancelled();
            Function function = functions.next();
            if (function.isThunk() && function.getSymbol().getSource() != SourceType.USER_DEFINED) {
                skipped.add(new SkippedFunction(function.getName(), SkipReason.THUNK));
                diagnostic.accept("Skipped thunk function " + function.getName() +
                    "; only explicitly analyst-named memory thunks are currently exported");
                continue;
            }
            AddressSetView body = function.getBody();
            AddressRangeIterator ranges = body.getAddressRanges(true);
            if (!ranges.hasNext()) {
                skipped.add(new SkippedFunction(function.getName(), SkipReason.BODYLESS));
                diagnostic.accept("Skipped bodyless/external function " + function.getName());
                continue;
            }
            AddressRange first = ranges.next();
            if (!first.getMinAddress().isMemoryAddress()) {
                skipped.add(new SkippedFunction(function.getName(), SkipReason.NON_MEMORY));
                diagnostic.accept("Skipped non-memory function " + function.getName());
                continue;
            }
            if (!function.getEntryPoint().isMemoryAddress() ||
                    !body.contains(function.getEntryPoint())) {
                skipped.add(new SkippedFunction(function.getName(),
                    SkipReason.ENTRY_OUTSIDE_BODY));
                diagnostic.accept("Skipped function whose entry point is outside its " +
                    "memory body " + function.getName());
                continue;
            }
            List<FunctionRange> translated = new ArrayList<>();
            AddressRange range = first;
            boolean valid = true;
            while (true) {
                if (!range.getMinAddress().isMemoryAddress()) {
                    valid = false;
                    break;
                }
                try {
                    translated.add(new FunctionRange(AddressNormalizer.toElfAddress(
                        range.getMinAddress().getOffset(), rebaseDelta), range.getLength()));
                }
                catch (ArithmeticException | IllegalArgumentException failure) {
                    valid = false;
                    break;
                }
                if (!ranges.hasNext()) {
                    break;
                }
                range = ranges.next();
            }
            if (!valid) {
                skipped.add(new SkippedFunction(function.getName(),
                    SkipReason.UNSUPPORTED_RANGE));
                diagnostic.accept("Skipped unsupported function range " + function.getName());
                continue;
            }
            long entry;
            try {
                entry = AddressNormalizer.toElfAddress(
                    function.getEntryPoint().getOffset(), rebaseDelta);
            }
            catch (ArithmeticException overflow) {
                skipped.add(new SkippedFunction(function.getName(),
                    SkipReason.UNTRANSLATABLE_ADDRESS));
                diagnostic.accept("Skipped untranslatable function " + function.getName());
                continue;
            }
            result.add(new FunctionSymbol(function.getName(), entry, translated,
                displayNamespacePath(function, diagnostic)));
        }
        // The ordinary iterator excludes external functions. Inventory them separately;
        // their qualified names are diagnostic identities, not emitted namespace DIEs.
        // Never interpret an external-space placeholder as an address in this image.
        List<String> externalNames = new ArrayList<>();
        FunctionIterator externals = program.getFunctionManager().getExternalFunctions();
        while (externals.hasNext()) {
            monitor.checkCancelled();
            externalNames.add(externals.next().getName(true));
        }
        externalNames.sort(String::compareTo);
        for (String name : externalNames) {
            monitor.checkCancelled();
            skipped.add(new SkippedFunction(name, SkipReason.EXTERNAL_IMPORT));
            diagnostic.accept("Skipped external/import function " + name +
                "; no in-image definition; curated declarations are emitted separately");
        }
        FunctionSymbol.validateDisplayNames(result);
        return new ExtractionResult(result, skipped);
    }

    private static List<String> displayNamespacePath(Function function,
            Consumer<String> diagnostic) {
        List<String> path = new ArrayList<>();
        for (Namespace scope = function.getParentNamespace();
                scope != null && !scope.isGlobal(); scope = scope.getParentNamespace()) {
            if (scope.getType() != Namespace.Type.NAMESPACE && scope.getType() != Namespace.Type.CLASS) {
                // Preserve the existing lexical-name behavior for scopes whose
                // semantics are not covered by this display-only policy.
                diagnostic.accept("Omitted function display namespace for " +
                    function.getName(true) + "; " + scope.getType().friendlyName() +
                    " scope is unsupported; retained lexical name " + function.getName());
                return List.of();
            }
            // This is the current analyst-visible path, not a C++ class DIE,
            // original linkage name, inheritance model or method declaration.
            path.add(0, scope.getName());
        }
        return List.copyOf(path);
    }
}
