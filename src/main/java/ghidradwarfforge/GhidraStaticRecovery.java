package ghidradwarfforge;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Same-pass inferred memory types; saved identity, never reference count, establishes ownership. */
public final class GhidraStaticRecovery {
    public record Candidate(long functionId, long symbolId, String name, SourceType source,
            Address address, DataType type) { }

    public record Result(List<Candidate> candidates, List<String> diagnostics) {
        public Result {
            candidates = List.copyOf(candidates);
            diagnostics = List.copyOf(diagnostics);
        }
    }

    private GhidraStaticRecovery() { }

    public static Result recover(HighFunction high, TaskMonitor monitor) throws CancelledException {
        if (high == null) return new Result(List.of(), List.of());
        var function = high.getFunction();
        Map<Long, List<HighVariable>> bySymbol = new HashMap<>();
        var seen = new HashSet<HighVariable>();
        // Inspect every associated high variable, not just HighSymbol's largest partial object.
        for (var space : function.getProgram().getAddressFactory().getAddressSpaces()) {
            monitor.checkCancelled();
            if (!space.isMemorySpace()) continue;
            var nodes = high.getVarnodes(space);
            while (nodes.hasNext()) {
                monitor.checkCancelled();
                var variable = nodes.next().getHigh();
                if (variable == null || !seen.add(variable) || variable.getSymbol() == null) continue;
                var saved = variable.getSymbol().getSymbol();
                if (saved == null || saved.getID() <= 0 || saved.getSource() == SourceType.DEFAULT ||
                        saved.getParentNamespace().getID() != function.getID() ||
                        !(saved.getParentNamespace() instanceof Function) ||
                        !(saved.getSymbolType() == SymbolType.LABEL || saved.getSymbolType() == SymbolType.LOCAL_VAR)) continue;
                bySymbol.computeIfAbsent(saved.getID(), unused -> new ArrayList<>()).add(variable);
            }
        }
        var candidates = new ArrayList<Candidate>();
        var diagnostics = new ArrayList<String>();
        for (long id : bySymbol.keySet().stream().sorted().toList()) {
            monitor.checkCancelled();
            var variables = bySymbol.get(id);
            var first = variables.getFirst();
            Symbol saved = first.getSymbol().getSymbol();
            DataType type = first.getDataType();
            Address address = first.getRepresentative().getAddress();
            boolean complete = type != null && !Undefined.isUndefined(type) && type.getLength() > 0 &&
                address.isMemoryAddress();
            for (var variable : variables) {
                monitor.checkCancelled();
                complete = complete && (variable.getOffset() == -1 || variable.getOffset() == 0) && variable.getSize() == type.getLength() &&
                    variable.getDataType().isEquivalent(type) && variable.getInstances().length > 0;
                for (var node : variable.getInstances()) {
                    monitor.checkCancelled();
                    complete = complete && node.getAddress().equals(address) && node.getSize() == type.getLength();
                }
            }
            if (complete) candidates.add(new Candidate(function.getID(), id, saved.getName(), saved.getSource(), address, type));
            else diagnostics.add("Omitted recovered static type for " + saved.getName(true) +
                ": partial, conflicting or undefined memory access");
        }
        candidates.sort(Comparator.comparingLong(Candidate::symbolId));
        return new Result(candidates, diagnostics);
    }

    /** Recheck saved identity and undefined extent at extraction; no saved Data is modified. */
    static DataType accept(Program program, Function owner, Symbol symbol, Address address,
            int exactSize, Candidate candidate, TaskMonitor monitor, Consumer<String> diagnostic)
            throws CancelledException {
        monitor.checkCancelled();
        if (candidate == null) return null;
        if (candidate.functionId() != owner.getID() || candidate.symbolId() != symbol.getID() ||
                !candidate.name().equals(symbol.getName()) || candidate.source() != symbol.getSource() ||
                !(symbol.getParentNamespace() instanceof Function) || symbol.getParentNamespace().getID() != owner.getID() ||
                !candidate.address().equals(address) || candidate.type() == null || Undefined.isUndefined(candidate.type()) ||
                candidate.type().getLength() <= 0 || (exactSize > 0 && candidate.type().getLength() != exactSize)) {
            diagnostic.accept("Omitted recovered static type for " + symbol.getName(true) + ": saved identity or extent changed");
            return null;
        }
        if (GhidraStaticBindings.read(program, symbol.getID(), monitor, diagnostic).status() != GhidraStaticBindings.Status.ABSENT) {
            return null;
        }
        try {
            var end = address.addNoWrap(candidate.type().getLength() - 1L);
            var block = program.getMemory().getBlock(address);
            if (block == null || !block.isLoaded() || !block.contains(end)) return null;
            var labels = program.getSymbolTable().getSymbolIterator(address, true);
            while (labels.hasNext()) {
                monitor.checkCancelled();
                var label = labels.next();
                if (label.getAddress().compareTo(end) > 0) break;
                if (label.getAddress().compareTo(address) > 0 && label.getSource() != SourceType.DEFAULT) {
                    diagnostic.accept("Omitted recovered static type for " + symbol.getName(true) + ": crosses another saved symbol");
                    return null;
                }
            }
            var units = program.getListing().getCodeUnits(new AddressSet(address, end), true);
            while (units.hasNext()) {
                monitor.checkCancelled();
                var unit = units.next();
                if (!(unit instanceof Data data) || !Undefined.isUndefined(data.getDataType())) {
                    diagnostic.accept("Omitted recovered static type for " + symbol.getName(true) + ": overlaps defined listing content");
                    return null;
                }
            }
            // The iterator need not include a code unit that starts before the requested range.
            var containing = program.getListing().getCodeUnitContaining(address);
            if (containing != null && (!(containing instanceof Data data) || !Undefined.isUndefined(data.getDataType()))) return null;
        }
        catch (ghidra.program.model.address.AddressOverflowException overflow) {
            return null;
        }
        diagnostic.accept("Using decompiler-recovered static type for " + symbol.getName(true) + ": " +
            candidate.type().getName() + "; saved function identity, inferred type; not original compiler facts");
        return candidate.type();
    }
}
