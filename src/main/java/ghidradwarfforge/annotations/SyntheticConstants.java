package ghidradwarfforge.annotations;

import java.util.List;
import java.util.Set;

/** Pure producer boundary, including additional consumer names observed during extraction. */
public record SyntheticConstants(List<SyntheticConstant> values, Set<String> reservedNames) {
    public SyntheticConstants {
        values = List.copyOf(values);
        reservedNames = Set.copyOf(reservedNames);
    }
}
