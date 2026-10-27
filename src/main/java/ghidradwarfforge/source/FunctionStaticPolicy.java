package ghidradwarfforge.source;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.ProgramTypeModel.FunctionStaticVariable;

/** Keep failed decompilations symbol-only in both DWARF and export reports. */
public final class FunctionStaticPolicy {
    private FunctionStaticPolicy() {
    }

    public record Selection(List<FunctionStaticVariable> exported, List<String> diagnostics) {
        public Selection {
            exported = List.copyOf(exported);
            diagnostics = List.copyOf(diagnostics);
        }
    }

    public static Selection select(ProgramTypeModel model, SyntheticSourceFile source) {
        if (model == null) {
            return new Selection(List.of(), List.of());
        }
        Set<Long> failedOwners = source == null ? Set.of() : source.functions().stream()
            .filter(function -> function.failureDiagnostic() != null)
            .map(SyntheticSourceFile.FunctionLines::address).collect(Collectors.toSet());
        List<FunctionStaticVariable> exported = new ArrayList<>();
        List<String> diagnostics = new ArrayList<>();
        for (FunctionStaticVariable variable : model.functionStatics()) {
            if (failedOwners.contains(variable.ownerAddress())) {
                diagnostics.add("Omitted function-owned static variable " + variable.name() +
                    " at 0x" + Long.toHexString(variable.address()) +
                    "; owning function at 0x" + Long.toHexString(variable.ownerAddress()) +
                    " failed decompilation and remains symbol-only");
            }
            else {
                exported.add(variable);
            }
        }
        return new Selection(exported, diagnostics);
    }
}
