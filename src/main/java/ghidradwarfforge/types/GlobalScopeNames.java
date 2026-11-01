package ghidradwarfforge.types;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** C11 lookup names remain separate from recorded namespace ownership. */
public final class GlobalScopeNames {
    public record Plan(Set<ProgramTypeModel.GlobalVariable> qualified,
            Set<ProgramTypeModel.GlobalVariable> shortAliases, List<String> diagnostics) {
        public Plan {
            qualified = Set.copyOf(qualified);
            shortAliases = Set.copyOf(shortAliases);
            diagnostics = List.copyOf(diagnostics);
        }
    }

    private GlobalScopeNames() { }

    public static String qualifiedName(ProgramTypeModel.GlobalVariable global) {
        return global.namespace().isEmpty() ? global.name() : String.join("::", global.namespace()) + "::" + global.name();
    }

    public static Plan build(List<ProgramTypeModel.GlobalVariable> globals, TypeGraph graph,
            List<String> reservedNames) {
        var fullCounts = new HashMap<String, Integer>();
        var shortCounts = new HashMap<String, Integer>();
        for (var global : globals) {
            fullCounts.merge(qualifiedName(global), 1, Integer::sum);
            shortCounts.merge(global.name(), 1, Integer::sum);
        }
        var reserved = new HashSet<>(reservedNames);
        var occupiedShort = new HashSet<>(reserved);
        for (var type : graph.nodes()) {
            reserved.add(type.name());
            occupiedShort.add(type.name());
            if (type instanceof TypeGraph.EnumType enumeration) {
                for (var value : enumeration.values()) {
                    reserved.add(value.name());
                    occupiedShort.add(value.name());
                }
            }
        }
        var qualified = new HashSet<ProgramTypeModel.GlobalVariable>();
        var aliases = new HashSet<ProgramTypeModel.GlobalVariable>();
        var diagnostics = new ArrayList<String>();
        for (var global : globals) {
            if (global.namespace().isEmpty()) continue;
            String name = qualifiedName(global);
            if (fullCounts.get(name) != 1 || reserved.contains(name)) {
                diagnostics.add("Omitted qualified global lookup " + name +
                    ": spelling conflicts with another symbol; original namespace/type/storage retained");
                continue;
            }
            qualified.add(global);
            // GDB flattens C11 imported leaf names after loading a CU. An
            // ambiguous leaf must not shadow a different global or function.
            if (shortCounts.get(global.name()) == 1 && !occupiedShort.contains(global.name())) aliases.add(global);
        }
        return new Plan(qualified, aliases, diagnostics);
    }
}
