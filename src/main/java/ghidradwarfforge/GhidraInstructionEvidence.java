package ghidradwarfforge;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.coverage.DecodedInstructions;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;

/** Captures actual listing starts using the same ELF normalization as functions. */
public final class GhidraInstructionEvidence {
    private record Key(String name, long address) {
    }

    private GhidraInstructionEvidence() {
    }

    public static List<DecodedInstructions> capture(Program program, List<FunctionSymbol> selected,
            long rebaseDelta, TaskMonitor monitor, Consumer<String> diagnostic)
            throws CancelledException {
        monitor.checkCancelled();
        if (selected.isEmpty()) return List.of();
        Map<Key, FunctionSymbol> wanted = new HashMap<>();
        for (var symbol : selected) {
            monitor.checkCancelled();
            if (wanted.put(new Key(symbol.name(), symbol.address()), symbol) != null) {
                throw new IllegalArgumentException("duplicate selected function identity");
            }
        }
        Map<Key, DecodedInstructions> captured = new HashMap<>();
        var functions = program.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            monitor.checkCancelled();
            var function = functions.next();
            long entry;
            try {
                entry = AddressNormalizer.toElfAddress(function.getEntryPoint().getOffset(), rebaseDelta);
            }
            catch (ArithmeticException failure) {
                continue;
            }
            Key key = new Key(function.getName(), entry);
            var symbol = wanted.get(key);
            if (symbol == null) continue;
            if (captured.containsKey(key)) {
                captured.put(key, unavailable(symbol, "Ambiguous function address-space identity"));
                continue;
            }
            try {
                var body = function.getBody();
                List<FunctionRange> ranges = new ArrayList<>();
                var rangeIterator = body.getAddressRanges(true);
                while (rangeIterator.hasNext()) {
                    monitor.checkCancelled();
                    var range = rangeIterator.next();
                    if (!range.getMinAddress().isMemoryAddress() ||
                            !range.getMinAddress().getAddressSpace().equals(
                                function.getEntryPoint().getAddressSpace())) {
                        throw new IllegalArgumentException("Unsupported mixed function address spaces");
                    }
                    ranges.add(new FunctionRange(AddressNormalizer.toElfAddress(
                        range.getMinAddress().getOffset(), rebaseDelta), range.getLength()));
                }
                if (!ranges.equals(symbol.ranges())) {
                    captured.put(key, unavailable(symbol, "Function body changed after symbol extraction"));
                    continue;
                }
                List<Long> starts = new ArrayList<>();
                var instructions = program.getListing().getInstructions(body, true);
                while (instructions.hasNext()) {
                    monitor.checkCancelled();
                    var instruction = instructions.next();
                    var address = instruction.getAddress();
                    if (!body.contains(address)) continue;
                    starts.add(AddressNormalizer.toElfAddress(address.getOffset(), rebaseDelta));
                }
                captured.put(key, new DecodedInstructions(symbol, starts, ""));
            }
            catch (ArithmeticException | IllegalArgumentException failure) {
                captured.put(key, unavailable(symbol, "Listing inventory unavailable: " + failure.getMessage()));
            }
        }
        List<DecodedInstructions> result = new ArrayList<>();
        for (var symbol : selected) {
            monitor.checkCancelled();
            var evidence = captured.get(new Key(symbol.name(), symbol.address()));
            if (evidence == null) {
                evidence = unavailable(symbol, "No matching function at the captured entry and name");
            }
            if (!evidence.available()) {
                diagnostic.accept("Source coverage unavailable for " + symbol.qualifiedDisplayName() +
                    ": " + evidence.unavailableReason());
            }
            result.add(evidence);
        }
        result.sort(Comparator.comparingLong((DecodedInstructions item) -> item.function().address())
            .thenComparing(item -> item.function().name()));
        return List.copyOf(result);
    }

    private static DecodedInstructions unavailable(FunctionSymbol function, String reason) {
        return new DecodedInstructions(function, List.of(), reason);
    }
}
