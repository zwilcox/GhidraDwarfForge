package ghidradwarfforge.coverage;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/** Declaration counts plus explicitly restricted known-scope variable-PC-byte totals. */
public record VariableCoverageTotals(long recoveredVariables, long emittedVariables,
        long variablesWithLocation, long knownScopeVariables, long unknownScopeVariables,
        Long knownScopeBytes, Long coveredScopeBytes, String extentUnavailableReason) {
    public VariableCoverageTotals {
        Objects.requireNonNull(extentUnavailableReason);
        if (recoveredVariables < 0 || emittedVariables < 0 || variablesWithLocation < 0 ||
                knownScopeVariables < 0 || unknownScopeVariables < 0 ||
                emittedVariables > recoveredVariables || variablesWithLocation > emittedVariables ||
                knownScopeVariables > recoveredVariables ||
                unknownScopeVariables != recoveredVariables - knownScopeVariables ||
                (knownScopeBytes == null) != (coveredScopeBytes == null)) {
            throw new IllegalArgumentException("inconsistent variable populations");
        }
        if (knownScopeBytes == null) {
            if (!extentUnavailableReason.equals("OVERFLOW")) {
                throw new IllegalArgumentException("unavailable extent needs an explicit overflow reason");
            }
        }
        else if (!extentUnavailableReason.isEmpty() || knownScopeBytes < 0 || coveredScopeBytes < 0 ||
                coveredScopeBytes > knownScopeBytes) {
            throw new IllegalArgumentException("inconsistent aggregate scope extent");
        }
    }

    public boolean variablePercentageApplicable() {
        return recoveredVariables != 0;
    }

    /** This percentage describes only knownScopeVariables, not the entire population. */
    public boolean knownScopePercentageApplicable() {
        return knownScopeBytes != null && knownScopeBytes != 0;
    }

    /** Supply one row per distinct recovered declaration, including declarations not emitted. */
    public static VariableCoverageTotals measure(List<LocationCoverage> declarations, BooleanSupplier cancelled) {
        Objects.requireNonNull(declarations);
        Objects.requireNonNull(cancelled);
        checkCancelled(cancelled);
        long emitted = 0;
        long located = 0;
        long known = 0;
        long unknown = 0;
        long denominator = 0;
        long numerator = 0;
        boolean overflow = false;
        for (LocationCoverage declaration : declarations) {
            checkCancelled(cancelled);
            if (declaration.declarationEmitted()) emitted++;
            if (declaration.hasFullValueLocation()) located++;
            if (declaration.scopeComplete()) {
                known++;
                if (!overflow) {
                    try {
                        denominator = Math.addExact(denominator, declaration.knownScopeBytes());
                        numerator = Math.addExact(numerator, declaration.coveredScopeBytes());
                    }
                    catch (ArithmeticException unavailable) {
                        overflow = true;
                    }
                }
            }
            else {
                unknown++;
            }
        }
        return new VariableCoverageTotals(declarations.size(), emitted, located, known, unknown,
            overflow ? null : denominator, overflow ? null : numerator, overflow ? "OVERFLOW" : "");
    }

    private static void checkCancelled(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("variable coverage totals cancelled");
    }
}
