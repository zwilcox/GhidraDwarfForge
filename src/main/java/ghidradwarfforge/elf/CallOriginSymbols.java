package ghidradwarfforge.elf;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

import ghidradwarfforge.calls.CallSitePlan;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.TypeGraph;

/** Sidecar-owned, exact-entry lookup names. These are not recovered original linkage. */
public final class CallOriginSymbols {
    private static final long MAX_IMAGE_HASH_BYTES = 1024L * 1024 * 1024;
    private static final long MAX_COMPARISONS = 16L * 1024 * 1024;

    private CallOriginSymbols() { }

    /** The target description must first authorize direct code-address symbol semantics. */
    public static List<ElfLocalFunctionSymbol> plan(ElfImage image, CallSitePlan calls,
            List<FunctionSymbol> functions, ProgramTypeModel types, List<ElfFunctionAlias> aliases,
            Set<String> reserved, BooleanSupplier cancelled, Consumer<String> diagnostic) throws IOException {
        check(cancelled);
        Set<Long> targets = new HashSet<>();
        for (var caller : calls.functions()) {
            check(cancelled);
            for (var site : caller.sites()) {
                check(cancelled);
                if (site.callee() != null) targets.add(site.callee());
            }
        }
        var selected = new ArrayList<FunctionSymbol>();
        for (var function : functions) {
            check(cancelled);
            if (function.usesRangeList() && targets.contains(function.address())) selected.add(function);
        }
        selected.sort(Comparator.comparingLong(FunctionSymbol::address));
        if (selected.isEmpty()) return List.of();
        if (image.type() != 2 && image.type() != 3 || image.fileSize() > MAX_IMAGE_HASH_BYTES) {
            diagnostic.accept("Omitted exact call-origin symbols: requires linked ELF within 1 GiB identity-hash budget");
            return List.of();
        }
        var allocations = new ArrayList<ElfLoadAllocations.Allocation>();
        if (image.sections().isEmpty()) allocations.addAll(ElfLoadAllocations.read(image, cancelled));
        else for (var section : image.sections()) {
            check(cancelled);
            allocations.add(new ElfLoadAllocations.Allocation(section, section.type == 1 ? section.size : 0));
        }
        long ranges = 0;
        var entryCounts = new java.util.HashMap<Long, Integer>();
        for (var function : functions) {
            check(cancelled);
            ranges += function.ranges().size();
            entryCounts.merge(function.address(), 1, Integer::sum);
        }
        if (selected.size() > 65536 || ranges + allocations.size() > MAX_COMPARISONS / selected.size()) {
            diagnostic.accept("Omitted exact call-origin symbols: allocation/ownership comparison budget exceeded");
            return List.of();
        }
        var model = types == null ? new ProgramTypeModel(new TypeGraph(List.of()), List.of(), List.of()) : types;
        EquateNameReservations names;
        try {
            names = EquateNameReservations.read(image, model, functions, aliases, cancelled, diagnostic)
                .withNames(reserved, cancelled);
        }
        catch (IllegalArgumentException unsupported) {
            diagnostic.accept("Omitted exact call-origin symbols: " + unsupported.getMessage());
            return List.of();
        }
        var result = new ArrayList<ElfLocalFunctionSymbol>();
        try (var input = FileChannel.open(image.sourcePath(), StandardOpenOption.READ)) {
            image.requireUnchanged(input);
            // Image identity prevents ordinary equal function names in other DSOs
            // from satisfying GDB's global minimal-symbol lookup. No path or ASLR
            // address enters the deterministic synthetic name.
            String identity = FunctionAliasSymbols.hash(input, 0, image.fileSize(), cancelled);
            for (var function : selected) {
                check(cancelled);
                var entryRange = function.ranges().stream().filter(r -> r.contains(function.address())).findFirst().orElseThrow();
                long size = entryRange.endExclusive() - function.address();
                ElfLoadAllocations.Allocation allocation = null;
                boolean ambiguous = entryCounts.get(function.address()) != 1;
                for (var candidate : allocations) {
                    check(cancelled);
                    var section = candidate.section();
                    if ((section.flags & 2) != 0 && intersects(function.address(), size, section.address, section.size)) {
                        if (allocation != null) ambiguous = true;
                        allocation = candidate;
                    }
                }
                for (var other : functions) {
                    check(cancelled);
                    if (other == function) continue;
                    for (var range : other.ranges()) {
                        check(cancelled);
                        if (intersects(function.address(), size, range.address(), range.size())) ambiguous = true;
                    }
                }
                if (ambiguous || allocation == null || (allocation.section().flags & 6) != 6 ||
                        function.address() < allocation.section().address ||
                        function.address() - allocation.section().address > allocation.fileSize() ||
                        size > allocation.fileSize() - (function.address() - allocation.section().address)) {
                    diagnostic.accept("Omitted exact call-origin symbol for " + function.qualifiedDisplayName() +
                        ": entry range lacks unique file-backed executable ownership");
                    continue;
                }
                String base = "forge_call_entry_" + identity + "_" + Long.toUnsignedString(function.address(), 16);
                String name = base;
                long suffix = 0;
                while (names.test(name)) {
                    check(cancelled);
                    if (++suffix > names.size()) throw new IllegalStateException("call-origin name reservation bound");
                    name = base + "_" + suffix;
                }
                result.add(new ElfLocalFunctionSymbol(name, function.address(), size, allocation.section().originalIndex));
            }
            image.requireUnchanged(input);
        }
        return List.copyOf(result);
    }

    private static boolean intersects(long a, long sizeA, long b, long sizeB) {
        return sizeA > 0 && sizeB > 0 && (a < b ? b - a < sizeA : a - b < sizeB);
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("call-origin symbol planning cancelled");
    }
}
