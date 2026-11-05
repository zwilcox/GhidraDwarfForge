package ghidradwarfforge.coverage;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import ghidradwarfforge.dwarf.Dwarf5LineTable;
import ghidradwarfforge.dwarf.Dwarf5LocationLists.PlannedRange;
import ghidradwarfforge.dwarf.DwarfLocationExpression.Expression;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.types.ProgramTypeModel.FunctionSignature;
import ghidradwarfforge.types.TypeGraph;
import ghidradwarfforge.types.TypeGraph.TypeRef;

/**
 * Immutable facts retained by successful production. No native pointers escape.
 * These describe emitted declarations/locations, not recovered populations or
 * complete lexical lifetimes. Public scorecards must supply those independently.
 */
public record ExportEmission(TypeGraph types, Map<String, List<TypeRef>> typeReferences,
        Dwarf5LineTable.Result lines, List<FunctionEmission> functions) {
    public ExportEmission {
        Objects.requireNonNull(types);
        Objects.requireNonNull(lines);
        Map<String, List<TypeRef>> references = new LinkedHashMap<>();
        typeReferences.forEach((key, values) -> references.put(key, List.copyOf(values)));
        typeReferences = Map.copyOf(references);
        functions = List.copyOf(functions);
    }

    public enum Kind {
        PARAMETER, LOCAL, FUNCTION_STATIC
    }

    public sealed interface Location permits NoLocation, ExpressionLocation, ListLocation {
    }

    public record NoLocation(String reason, String diagnostic) implements Location {
        public NoLocation {
            if (reason == null || reason.isBlank() || diagnostic == null || diagnostic.isBlank()) {
                throw new IllegalArgumentException("missing location omission reason");
            }
        }
    }

    /** An expression has no encoded address interval; do not invent a lifetime here. */
    public record ExpressionLocation(Expression expression) implements Location {
        public ExpressionLocation {
            Objects.requireNonNull(expression);
        }
    }

    /** Only the exact successfully referenced list ranges count as emitted. */
    public record ListLocation(long offset, List<PlannedRange> ranges) implements Location {
        public ListLocation {
            if (offset < 0 || ranges == null || ranges.isEmpty()) {
                throw new IllegalArgumentException("invalid emitted location list");
            }
            ranges = List.copyOf(ranges);
        }
    }

    /**
     * Parameter ordinal survives blank/duplicate display names. Local internal
     * names retain extraction's disambiguation; block/name identifies statics.
     * Return-buffer carriers remain in the recovered parameter population even
     * though their actual DIE is an artificial DW_TAG_variable.
     */
    public record VariableEmission(Kind kind, int parameterOrdinal, String internalName,
            String displayName, String block, TypeRef type, boolean artificial,
            boolean returnStorage, Location location) {
        public VariableEmission {
            Objects.requireNonNull(kind);
            Objects.requireNonNull(internalName);
            Objects.requireNonNull(displayName);
            Objects.requireNonNull(block);
            Objects.requireNonNull(type);
            Objects.requireNonNull(location);
            if ((kind == Kind.PARAMETER ? parameterOrdinal < 0 : parameterOrdinal != -1) ||
                    (returnStorage && (!artificial || kind != Kind.PARAMETER))) {
                throw new IllegalArgumentException("invalid emitted variable identity");
            }
        }
    }

    /** A null signature explicitly records a symbol-only function. */
    public record FunctionEmission(FunctionSymbol function, FunctionSignature signature,
            List<VariableEmission> variables) {
        public FunctionEmission {
            Objects.requireNonNull(function);
            variables = List.copyOf(variables);
        }

        public List<TypeRef> typeRoots() {
            List<TypeRef> roots = new ArrayList<>();
            if (signature != null) roots.add(signature.returnType());
            for (VariableEmission variable : variables) roots.add(variable.type());
            return List.copyOf(roots);
        }
    }
}
