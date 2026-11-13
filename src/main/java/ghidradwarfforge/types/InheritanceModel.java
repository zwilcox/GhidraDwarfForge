package ghidradwarfforge.types;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import ghidradwarfforge.targets.CxxAbiProfile;
import ghidradwarfforge.types.ClassScopeModel.BindingSource;
import ghidradwarfforge.types.ClassScopeModel.FunctionReference;
import ghidradwarfforge.types.TypeGraph.AggregateType;
import ghidradwarfforge.types.TypeGraph.Parameter;

/** Explicit class relationships; neither a type name nor a function-pointer array is evidence. */
public record InheritanceModel(CxxAbiProfile abi, List<Base> bases, List<VirtualMethod> virtualMethods) {
    public enum Access { PUBLIC, PROTECTED, PRIVATE }
    public enum Virtuality { VIRTUAL, PURE_VIRTUAL }

    public sealed interface BaseLocation permits FixedBase, VirtualBase { }

    /** Occupied bytes exclude reusable tail padding and separately placed virtual bases. */
    public record FixedBase(long offset, long occupiedBytes) implements BaseLocation {
        public FixedBase {
            if (offset < 0 || occupiedBytes < 0) throw invalid("negative fixed base extent");
        }
    }

    /** Byte offsets from the subobject to its vptr and from the address point to a vbase entry. */
    public record VirtualBase(long vptrOffset, long slotOffset) implements BaseLocation {
        public VirtualBase {
            if (vptrOffset < 0 || slotOffset >= 0) throw invalid("invalid virtual base offsets");
        }
    }

    /** Declaration order is semantic; it must not be replaced by address/name ordering. */
    public record Base(long derivedClassId, long baseClassId, int order, Access access,
            BaseLocation location, String evidence) {
        public Base {
            if (derivedClassId <= 0 || baseClassId <= 0 || derivedClassId == baseClassId ||
                    order < 0 || order >= 65536 || access == null || location == null) {
                throw invalid("invalid base identity or declaration order");
            }
            provenance(evidence);
        }
    }

    /** Slot is the entry index in this class's table, not an executable address. */
    public record VirtualMethod(long methodId, int slot, Access access, Virtuality virtuality, String evidence) {
        public VirtualMethod {
            if (methodId <= 0 || slot < 0 || slot >= 65536 || access == null || virtuality == null) {
                throw invalid("invalid virtual method identity or slot");
            }
            provenance(evidence);
        }
    }

    public static InheritanceModel empty() {
        return new InheritanceModel(CxxAbiProfile.UNSPECIFIED, List.of(), List.of());
    }

    public InheritanceModel {
        if (abi == null || bases == null || virtualMethods == null || bases.size() > 65536 ||
                virtualMethods.size() > 65536 ||
                (abi == CxxAbiProfile.UNSPECIFIED && (!bases.isEmpty() || !virtualMethods.isEmpty()))) {
            throw invalid("missing or excessive inheritance model, or unspecified ABI");
        }
        var edges = new HashMap<Long, List<Long>>();
        var incoming = new HashMap<Long, Integer>();
        var pairs = new HashSet<List<Long>>();
        var orders = new HashMap<Long, HashSet<Integer>>();
        for (var base : bases) {
            if (base == null || !pairs.add(List.of(base.derivedClassId(), base.baseClassId())) ||
                    !orders.computeIfAbsent(base.derivedClassId(), ignored -> new HashSet<>()).add(base.order())) {
                throw invalid("duplicate direct base or declaration order");
            }
            incoming.putIfAbsent(base.derivedClassId(), 0);
            incoming.merge(base.baseClassId(), 1, Integer::sum);
            edges.computeIfAbsent(base.derivedClassId(), ignored -> new ArrayList<>()).add(base.baseClassId());
        }
        for (var values : orders.values()) {
            for (int order = 0; order < values.size(); order++) {
                if (!values.contains(order)) throw invalid("missing base declaration order");
            }
        }
        var ready = new ArrayDeque<Long>();
        incoming.forEach((id, count) -> { if (count == 0) ready.add(id); });
        int visited = 0;
        while (!ready.isEmpty()) {
            long id = ready.removeFirst();
            visited++;
            for (long parent : edges.getOrDefault(id, List.of())) {
                if (incoming.merge(parent, -1, Integer::sum) == 0) ready.add(parent);
            }
        }
        if (visited != incoming.size()) throw invalid("cyclic inheritance graph");
        var methodIds = new HashSet<Long>();
        for (var method : virtualMethods) {
            if (method == null || !methodIds.add(method.methodId())) throw invalid("duplicate virtual method identity");
        }
        bases = bases.stream().sorted(Comparator.comparingLong(Base::derivedClassId).thenComparingInt(Base::order)).toList();
        virtualMethods = virtualMethods.stream().sorted(Comparator.comparingLong(VirtualMethod::methodId)).toList();
    }

    /** Called after ordinary class/signature validation; names never join these records. */
    void validate(TypeGraph graph, ClassScopeModel classes, Map<FunctionReference, List<Parameter>> signatures) {
        var layouts = new HashMap<Long, AggregateType>();
        var types = graph.byKey();
        for (var binding : classes.bindings()) {
            if (binding.source() == BindingSource.EXPLICIT_SAVED) {
                layouts.put(binding.classId(), (AggregateType) types.get(binding.type().key()));
            }
        }
        for (var base : bases) {
            var derived = layout(layouts, base.derivedClassId());
            var parent = layout(layouts, base.baseClassId());
            if (base.location() instanceof FixedBase fixed) {
                // Base subobjects may overlap reusable tail padding or have no
                // occupied bytes. sizeof(base) is not its occupied extent here.
                if (fixed.offset() >= derived.byteSize() || fixed.occupiedBytes() > parent.byteSize() ||
                        fixed.occupiedBytes() > derived.byteSize() - fixed.offset()) {
                    throw invalid("base subobject exceeds evidenced class extent");
                }
            }
            else if (base.location() instanceof VirtualBase virtual) {
                abi.requireVirtualBase(virtual.vptrOffset(), virtual.slotOffset(), derived.byteSize());
            }
        }
        var methods = new HashMap<Long, ClassScopeModel.Method>();
        for (var method : classes.methods()) methods.put(method.id(), method);
        var slots = new HashSet<List<Long>>();
        for (var virtual : virtualMethods) {
            var method = methods.get(virtual.methodId());
            if (method == null) throw invalid("virtual method identity is not present");
            layout(layouts, method.classId());
            var parameters = signatures.get(method.function());
            if (parameters == null || parameters.stream().noneMatch(Parameter::objectPointer)) {
                throw invalid("virtual method lacks a validated object parameter");
            }
            if (!slots.add(List.of(method.classId(), (long) virtual.slot()))) {
                throw invalid("conflicting virtual slot for one class");
            }
        }
    }

    private static AggregateType layout(Map<Long, AggregateType> layouts, long id) {
        var type = layouts.get(id);
        if (type == null || type.byteSize() <= 0) throw invalid("inheritance requires an explicit saved class layout");
        return type;
    }

    private static void provenance(String value) {
        if (value == null || value.isBlank() || value.length() > 8192 || value.indexOf('\0') >= 0) {
            throw invalid("inheritance requires bounded provenance");
        }
    }

    private static IllegalArgumentException invalid(String message) {
        return new IllegalArgumentException(message);
    }
}
