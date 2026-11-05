package ghidradwarfforge.coverage;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeSet;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

import ghidradwarfforge.dwarf.Dwarf5LineTable;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.source.SyntheticSourceFile;
import ghidradwarfforge.source.SyntheticSourceFile.FunctionLines;
import ghidradwarfforge.source.SyntheticSourceFile.FunctionTokens;

/** Known source populations plus explicit missing evidence; no probability or execution counts. */
public record SourceCoverageInventory(List<FunctionInventory> functions, Union observedUnion) {
    public SourceCoverageInventory {
        functions = List.copyOf(functions);
        Objects.requireNonNull(observedUnion);
    }

    /** Null counters mean unavailable, whereas a known empty population has zero counts. */
    public record FunctionInventory(FunctionSymbol function, String disposition, String diagnostic,
            Long decodedInstructions, Long anchoredInstructions, Long lineVisibleInstructions,
            String instructionUnavailableReason, String tokenUnavailableReason,
            SourceCoverageIndex.Points observedPoints) {
        public FunctionInventory {
            Objects.requireNonNull(function);
            Objects.requireNonNull(disposition);
            Objects.requireNonNull(diagnostic);
            Objects.requireNonNull(instructionUnavailableReason);
            Objects.requireNonNull(tokenUnavailableReason);
            if ((decodedInstructions == null) != !instructionUnavailableReason.isEmpty() ||
                    (decodedInstructions == null) != (lineVisibleInstructions == null) ||
                    (decodedInstructions == null) != (observedPoints == null) ||
                    (anchoredInstructions == null) !=
                        (decodedInstructions == null || !tokenUnavailableReason.isEmpty())) {
                throw new IllegalArgumentException("inconsistent unavailable source counts");
            }
            if (observedPoints != null) {
                var counts = observedPoints.counts();
                if (decodedInstructions != counts.decodedInstructions() ||
                        lineVisibleInstructions != counts.lineVisibleInstructions() ||
                        (anchoredInstructions != null && anchoredInstructions != counts.anchoredInstructions())) {
                    throw new IllegalArgumentException("source counts differ from observed points");
                }
            }
        }

        public boolean tokenPercentageApplicable() {
            return decodedInstructions != null && decodedInstructions != 0 && anchoredInstructions != null;
        }

        public boolean visibilityPercentageApplicable() {
            return decodedInstructions != null && decodedInstructions != 0;
        }
    }

    /**
     * Union counts describe only observed starts. Missing functions/evidence are
     * disclosed, never hidden by summing the functions that happened to succeed.
     * Per-function overlaps are valid; a program instruction is counted once.
     */
    public record Union(long functions, long unavailableInstructionFunctions, long unavailableTokenFunctions,
            long decodedInstructions, long anchoredInstructions, long lineVisibleInstructions) {
        public Union {
            if (functions < 0 || unavailableInstructionFunctions < 0 || unavailableTokenFunctions < 0 ||
                    unavailableInstructionFunctions > functions || unavailableTokenFunctions > functions) {
                throw new IllegalArgumentException("invalid source function populations");
            }
            new SourceCoverage(decodedInstructions, anchoredInstructions, lineVisibleInstructions);
        }

        public boolean tokenPercentageApplicable() {
            return decodedInstructions != 0 && unavailableInstructionFunctions == 0 && unavailableTokenFunctions == 0;
        }

        public boolean visibilityPercentageApplicable() {
            return decodedInstructions != 0 && unavailableInstructionFunctions == 0;
        }
    }

    private record Key(String name, long address) { }

    public static SourceCoverageInventory build(List<FunctionSymbol> primaryFunctions,
            List<DecodedInstructions> decoded, SyntheticSourceFile source, Dwarf5LineTable.Result emitted,
            BooleanSupplier cancelled) {
        check(cancelled);
        Map<Key, DecodedInstructions> instructions = new HashMap<>();
        for (var item : decoded) {
            check(cancelled);
            unique(instructions, key(item.function()), item, "instruction inventory");
        }
        Map<Key, FunctionLines> boundaries = new HashMap<>();
        Map<Key, FunctionTokens> tokens = new HashMap<>();
        if (source != null) {
            for (var boundary : source.functions()) {
                check(cancelled);
                unique(boundaries, new Key(boundary.name(), boundary.address()), boundary, "source function");
            }
            for (var token : source.functionTokens()) {
                check(cancelled);
                unique(tokens, new Key(token.name(), token.address()), token, "token provenance");
            }
        }
        var index = new SourceCoverageIndex(emitted, cancelled);
        var addresses = new HashSet<Long>();
        var allDecoded = new TreeSet<Long>();
        var allAnchored = new TreeSet<Long>();
        var allVisible = new TreeSet<Long>();
        long unknownInstructions = 0;
        long unknownTokens = 0;
        List<FunctionInventory> functions = new ArrayList<>();
        for (FunctionSymbol function : primaryFunctions) {
            check(cancelled);
            if (!addresses.add(function.address())) throw invalid("duplicate primary entry/alias population");
            Key key = key(function);
            var listing = instructions.remove(key);
            var boundary = boundaries.remove(key);
            var token = tokens.remove(key);
            if (listing != null && !listing.function().equals(function)) {
                throw invalid("instruction inventory describes another function body or namespace");
            }
            if (token != null && boundary == null) throw invalid("token provenance has no source function");
            if (token != null && !boundary.decompiled() && !token.lines().isEmpty()) {
                throw invalid("unavailable function has token mappings");
            }
            if (token != null) {
                for (var line : token.lines()) {
                    check(cancelled);
                    if (line.line() < boundary.startLine() || line.line() > boundary.endLine()) {
                        throw invalid("token mapping outside its source function");
                    }
                }
            }
            String disposition = boundary == null ? "UNAVAILABLE" : boundary.decompiled() ? "DECOMPILED" :
                boundary.failureDiagnostic() != null ? "FAILED" : "OMITTED";
            String diagnostic = boundary == null ? "No synthetic-source disposition was captured" :
                boundary.decompiled() ? "" : boundary.failureDiagnostic() != null ? boundary.failureDiagnostic() :
                boundary.omissionDiagnostic();
            String instructionReason = listing == null ? "NO_INSTRUCTION_INVENTORY" : listing.unavailableReason();
            String tokenReason = token == null ? "NO_TOKEN_PROVENANCE" : "";
            if (!instructionReason.isEmpty()) unknownInstructions++;
            if (!tokenReason.isEmpty()) unknownTokens++;
            SourceCoverageIndex.Points points = null;
            if (instructionReason.isEmpty()) {
                points = index.measurePoints(function, listing.starts(), token == null ? List.of() : token.lines(), cancelled);
                add(allDecoded, points.decoded(), cancelled);
                add(allAnchored, points.anchored(), cancelled);
                add(allVisible, points.lineVisible(), cancelled);
            }
            functions.add(new FunctionInventory(function, disposition, diagnostic,
                points == null ? null : (long) points.decoded().size(),
                points == null || !tokenReason.isEmpty() ? null : (long) points.anchored().size(),
                points == null ? null : (long) points.lineVisible().size(), instructionReason, tokenReason, points));
        }
        if (!instructions.isEmpty() || !boundaries.isEmpty() || !tokens.isEmpty()) {
            throw invalid("evidence refers to a function outside the primary population");
        }
        return new SourceCoverageInventory(functions, new Union(functions.size(), unknownInstructions, unknownTokens,
            allDecoded.size(), allAnchored.size(), allVisible.size()));
    }

    private static void add(TreeSet<Long> output, List<Long> values, BooleanSupplier cancelled) {
        for (long value : values) {
            check(cancelled);
            output.add(value);
        }
    }

    private static Key key(FunctionSymbol function) {
        return new Key(function.name(), function.address());
    }

    private static <K, V> void unique(Map<K, V> map, K key, V value, String subject) {
        if (map.putIfAbsent(key, value) != null) throw invalid("ambiguous " + subject);
    }

    private static IllegalArgumentException invalid(String message) {
        return new IllegalArgumentException(message);
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("source inventory cancelled");
    }
}
