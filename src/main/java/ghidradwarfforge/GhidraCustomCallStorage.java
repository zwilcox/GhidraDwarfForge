package ghidradwarfforge;

import ghidra.program.model.data.AbstractFloatDataType;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** A custom storage layout is not callable merely because its convention name says default. */
public final class GhidraCustomCallStorage {
    private GhidraCustomCallStorage() {
    }

    /** Empty means no additional custom-storage restriction, not general ABI certification. */
    public static String restriction(Program program, Function function, TaskMonitor monitor)
            throws CancelledException {
        monitor.checkCancelled();
        if (!function.hasCustomVariableStorage()) {
            return "";
        }
        var selected = function.getCallingConvention();
        var fallback = program.getCompilerSpec().getDefaultCallingConvention();
        if (selected == null || fallback == null || selected.isErrorPlaceholder() ||
                fallback.isErrorPlaceholder() || !selected.getName().equals(fallback.getName())) {
            return "custom storage has no resolved default calling-convention model";
        }
        if (function.hasVarArgs()) {
            return "custom variadic storage has no validated debugger ABI mapping";
        }
        var parameters = function.getParameters();
        if (parameters.length > 4096) {
            return "custom signature exceeds the parameter classification budget";
        }
        DataType[] types = new DataType[parameters.length + 1];
        types[0] = function.getReturn().getFormalDataType();
        for (int index = 0; index < parameters.length; index++) {
            monitor.checkCancelled();
            if (parameters[index].isAutoParameter()) {
                return "custom automatic parameters have no validated debugger ABI mapping";
            }
            types[index + 1] = parameters[index].getFormalDataType();
        }
        for (int index = 0; index < types.length; index++) {
            monitor.checkCancelled();
            if (!scalar(types[index], index == 0)) {
                return "custom " + (index == 0 ? "return" : "parameter " + (index - 1)) +
                    " type has no validated debugger ABI classification";
            }
        }
        VariableStorage[] expected;
        try {
            // Pinned Ghidra 12.0.3 API: return first, then ordered parameters.
            // Auto/forced-indirect assignments are checked below, never guessed.
            expected = fallback.getStorageLocations(program, types, true);
        }
        catch (IllegalArgumentException | IllegalStateException unsupported) {
            return "default prototype cannot classify the custom signature storage";
        }
        monitor.checkCancelled();
        if (expected == null || expected.length != types.length) {
            return "custom signature disagrees with default automatic parameter allocation";
        }
        for (int index = 0; index < expected.length; index++) {
            monitor.checkCancelled();
            var actual = index == 0 ? function.getReturn().getVariableStorage() :
                parameters[index - 1].getVariableStorage();
            var normal = expected[index];
            if (normal == null || actual == null || !normal.isValid() || !actual.isValid() ||
                    normal.isAutoStorage() || actual.isAutoStorage() ||
                    normal.isForcedIndirect() || actual.isForcedIndirect() || !normal.equals(actual)) {
                return "custom " + (index == 0 ? "return" : "parameter " + (index - 1)) +
                    " storage differs from or cannot be proved equivalent to the default prototype";
            }
        }
        return "";
    }

    private static boolean scalar(DataType type, boolean allowVoid) {
        java.util.Set<DataType> visited = java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<>());
        while (type instanceof TypeDef alias) {
            if (!visited.add(type) || visited.size() > 64) {
                return false;
            }
            type = alias.getBaseDataType();
        }
        return type != null && !Undefined.isUndefined(type) &&
            ((allowVoid && type instanceof VoidDataType) ||
                (type.getLength() > 0 && (type instanceof AbstractIntegerDataType ||
                    type instanceof AbstractFloatDataType || type instanceof BooleanDataType ||
                    type instanceof Pointer || type instanceof Enum)));
    }
}
