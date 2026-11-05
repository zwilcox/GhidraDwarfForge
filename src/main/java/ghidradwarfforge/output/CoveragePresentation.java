package ghidradwarfforge.output;

import java.math.BigDecimal;
import java.math.RoundingMode;
import ghidradwarfforge.coverage.ExportCoverage;
import ghidradwarfforge.coverage.TypeCoverage;
import ghidradwarfforge.coverage.VariableCoverageTotals;

/** Plain text shared by coverage views; percentages are static populations, never confidence. */
public final class CoveragePresentation {
    public static final String[] COLUMNS = {"Function", "ELF entry", "Source", "Token anchors",
        "Line visibility", "Variables located", "Known-scope PC bytes", "Resolved types"};
    private CoveragePresentation() { }

    public static String ratio(Long numerator, Long denominator) {
        if (numerator == null || denominator == null) return "Unknown";
        if (numerator < 0 || denominator < 0 || numerator > denominator) {
            throw new IllegalArgumentException("invalid coverage ratio");
        }
        if (denominator == 0) return "N/A (0/0)";
        // Round down: an incomplete population must never be presented as 100%.
        String percent = BigDecimal.valueOf(numerator).multiply(BigDecimal.valueOf(100))
            .divide(BigDecimal.valueOf(denominator), 2, RoundingMode.DOWN).toPlainString();
        return percent + "% (" + numerator + "/" + denominator + ")";
    }

    private static String scopes(VariableCoverageTotals totals) {
        return ratio(totals.coveredScopeBytes(), totals.knownScopeBytes()) +
            "; " + totals.unknownScopeVariables() + " unknown scopes excluded" +
            (totals.extentUnavailableReason().isEmpty() ? "" : "; " + totals.extentUnavailableReason());
    }

    private static String types(TypeCoverage types) {
        return types == null ? "Unknown" : ratio(types.resolvedEmittedNodes(), types.recoveredNodes()) +
            "; " + types.opaqueEmittedNodes() + " opaque, " + types.notEmittedNodes() + " not emitted";
    }

    public static String cell(ExportCoverage.Function function, int column) {
        var source = function.source();
        var variables = function.variables().totals();
        return switch (column) {
            case 0 -> function.function().qualifiedDisplayName();
            case 1 -> "0x" + Long.toHexString(function.function().address());
            case 2 -> source.disposition();
            case 3 -> ratio(source.anchoredInstructions(), source.decodedInstructions());
            case 4 -> ratio(source.lineVisibleInstructions(), source.decodedInstructions());
            case 5 -> ratio(variables.variablesWithLocation(), variables.recoveredVariables());
            case 6 -> scopes(variables);
            case 7 -> types(function.types());
            default -> throw new IndexOutOfBoundsException(column);
        };
    }

    public static String summary(CoverageReportClaims claims, String status) {
        var coverage = claims.coverage();
        var source = coverage.sourceUnion();
        String anchors = source.unavailableInstructionFunctions() == 0 && source.unavailableTokenFunctions() == 0
            ? ratio(source.anchoredInstructions(), source.decodedInstructions()) : "Unknown (incomplete evidence)";
        String visible = source.unavailableInstructionFunctions() == 0
            ? ratio(source.lineVisibleInstructions(), source.decodedInstructions()) : "Unknown (incomplete evidence)";
        return "Status: " + status + "; independent validation: NOT_RUN\n" +
            "Static address coverage; not execution coverage or a probability of correctness.\n" +
            "Functions: " + coverage.functions().size() + "; profile: " + displayName(claims.profile().languageId()) +
            " / " + displayName(claims.profile().compilerSpecId()) + "\n" +
            "Decoded instruction token anchors: " + anchors + "; line visibility: " + visible + "\n" +
            "Variables with a valid location: " + ratio(coverage.variables().variablesWithLocation(),
                coverage.variables().recoveredVariables()) + "\n" +
            "Known-scope variable-PC bytes: " + scopes(coverage.variables()) + "\n" +
            "Canonical function types: " + (coverage.unknownSignatureFunctions() == 0 ? types(coverage.functionTypeUnion()) :
                "Unknown (" + coverage.unknownSignatureFunctions() + " unavailable signatures)") + "\n" +
            "Select a function for provenance and omission reasons. Save report retains all evidence.";
    }

    /** Bound display work only; the saved report retains every field and range. */
    public static String details(ExportCoverage.Function function) {
        var text = new DisplayText();
        text.line("Function: " + function.function().qualifiedDisplayName());
        text.line("ELF entry: 0x" + Long.toHexString(function.function().address()));
        for (int column = 3; column < COLUMNS.length; column++) {
            text.line(COLUMNS[column] + ": " + cell(function, column));
        }
        text.line("Source: " + function.source().disposition() + "; " + function.source().diagnostic());
        text.line("Instruction evidence: " + function.source().instructionUnavailableReason());
        text.line("Token evidence: " + function.source().tokenUnavailableReason());
        text.line("Signature provenance: " + function.signature().source());
        text.line("Type provenance: " + function.typeProvenance());
        text.line("Debugger call restriction: " + function.signature().debuggerCallRestriction());
        for (var variable : function.variables().variables()) {
            if (text.full()) break;
            text.line("\n" + variable.identity().kind() + " " + variable.displayName() +
                " [" + variable.identity().internalName() + "; block=" + variable.identity().block() + "]");
            text.line("Declaration: " + variable.declarationProvenance().category() + "; " +
                variable.declarationProvenance().source() + "; " + variable.declarationProvenance().subject());
            text.line("Recovered type: " + variable.recoveredType().key());
            var location = variable.location();
            text.line("Location: " + (location.hasFullValueLocation() ? "available over evidenced ranges" : "unavailable") +
                "; scope: " + (location.scopeComplete() ? ratio(location.coveredScopeBytes(), location.knownScopeBytes()) :
                    "Unknown (percentage withheld)") + "; " + location.scopeEvidence());
            text.line("Omission: " + variable.omissionReason() + "; " + variable.diagnostic());
            for (var evidence : variable.storageEvidence()) {
                if (text.full()) break;
                text.line("  0x" + Long.toHexString(evidence.start()) + "..0x" + Long.toHexString(evidence.end()) +
                    ": " + evidence.category() + "; " + evidence.source() + "; " +
                    evidence.omissionReason() + "; " + evidence.diagnostic());
            }
        }
        return text.result();
    }

    private static String displayName(String value) {
        if (value.length() <= 512) return value;
        int end = Character.isHighSurrogate(value.charAt(511)) ? 511 : 512;
        return value.substring(0, end) + "… (full value in saved report)";
    }

    private static final class DisplayText {
        private static final int LIMIT = 32 * 1024;
        private final StringBuilder text = new StringBuilder();
        private boolean clipped;
        boolean full() { return clipped || text.length() >= LIMIT; }
        void line(String line) {
            if (full()) return;
            int length = Math.min(line.length(), LIMIT - text.length());
            if (length > 0 && Character.isHighSurrogate(line.charAt(length - 1))) length--;
            text.append(line, 0, length);
            if (length < line.length()) { clipped = true; text.setLength(Math.min(text.length(), LIMIT)); }
            if (text.length() < LIMIT) text.append('\n');
        }
        String result() {
            return text + (clipped || full() ? "\nDisplay limit reached. Save report for complete evidence.\n" : "");
        }
    }
}
