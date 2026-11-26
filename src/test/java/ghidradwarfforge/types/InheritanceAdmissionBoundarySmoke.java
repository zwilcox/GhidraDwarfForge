package ghidradwarfforge.types;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import ghidradwarfforge.targets.CxxAbiProfile;
import ghidradwarfforge.types.InheritanceModel.Access;
import ghidradwarfforge.types.InheritanceModel.Base;
import ghidradwarfforge.types.InheritanceModel.FixedBase;
import ghidradwarfforge.types.InheritanceModel.VirtualBase;
import ghidradwarfforge.types.InheritanceModel.VirtualMethod;
import ghidradwarfforge.types.InheritanceModel.Virtuality;

/** Admission and ownership of analyst evidence, without claiming a runtime C++ layout. */
public final class InheritanceAdmissionBoundarySmoke {
    private static final CxxAbiProfile ABI = CxxAbiProfile.ITANIUM_X86_64;
    private static final String EVIDENCE = "saved analyst relationship";
    private static int checks;

    public static void main(String[] args) {
        identitiesAndProvenance();
        capacityAndOwnership();
        vtableWitnessRanges();
        System.out.println("inheritance-admission-boundaries=PASS checks=" + checks);
    }

    private static Base base(long derived, long parent, int order) {
        return new Base(derived, parent, order, Access.PUBLIC, new FixedBase(0, 0), EVIDENCE);
    }

    private static VirtualMethod method(long id, int slot) {
        return new VirtualMethod(id, slot, Access.PUBLIC, Virtuality.VIRTUAL, EVIDENCE);
    }

    private static void identitiesAndProvenance() {
        // Identity is saved-program identity; zero/negative IDs must not become names or addresses.
        for (long invalid : new long[] {0, -1, Long.MIN_VALUE}) {
            rejects(() -> base(invalid, 1, 0), "derived identity");
            rejects(() -> base(1, invalid, 0), "parent identity");
            rejects(() -> method(invalid, 0), "method identity");
        }
        for (int invalid : new int[] {-1, 65536, Integer.MAX_VALUE}) {
            rejects(() -> base(2, 1, invalid), "declaration index");
            rejects(() -> method(1, invalid), "table slot");
        }
        rejects(() -> new Base(2, 1, 0, null, new FixedBase(0, 0), EVIDENCE), "missing base access");
        rejects(() -> new Base(2, 1, 0, Access.PUBLIC, null, EVIDENCE), "missing base location");
        rejects(() -> new VirtualMethod(1, 0, null, Virtuality.VIRTUAL, EVIDENCE), "missing method access");
        rejects(() -> new VirtualMethod(1, 0, Access.PUBLIC, null, EVIDENCE), "missing virtuality");
        rejects(() -> new FixedBase(0, -1), "negative occupied bytes");
        rejects(() -> new VirtualBase(-1, -24), "negative vptr offset");
        for (String invalid : Arrays.asList(null, "", " \n\t", "saved\0relationship", "a".repeat(8193))) {
            rejects(() -> new Base(2, 1, 0, Access.PUBLIC, new FixedBase(0, 0), invalid), "base provenance");
            rejects(() -> new VirtualMethod(1, 0, Access.PUBLIC, Virtuality.VIRTUAL, invalid), "method provenance");
        }
        String boundary = "a".repeat(8192);
        check(new Base(Long.MAX_VALUE, 1, 65535, Access.PRIVATE, new FixedBase(0, 0), boundary)
            .evidence().equals(boundary), "last valid base evidence and declaration index");
        check(new VirtualMethod(Long.MAX_VALUE, 65535, Access.PROTECTED, Virtuality.PURE_VIRTUAL, boundary)
            .evidence().equals(boundary), "last valid virtual method evidence and slot");
    }

    private static void capacityAndOwnership() {
        rejects(() -> new InheritanceModel(null, List.of(), List.of()), "missing ABI");
        rejects(() -> new InheritanceModel(ABI, null, List.of()), "missing bases");
        rejects(() -> new InheritanceModel(ABI, List.of(), null), "missing methods");
        rejects(() -> new InheritanceModel(ABI, Arrays.asList((Base) null), List.of()), "null base element");
        rejects(() -> new InheritanceModel(ABI, List.of(), Arrays.asList((VirtualMethod) null)), "null method element");
        rejects(() -> new InheritanceModel(CxxAbiProfile.UNSPECIFIED, List.of(), List.of(method(1, 0))),
            "virtual-only model still requires ABI");
        check(InheritanceModel.empty().bases().isEmpty() && InheritanceModel.empty().virtualMethods().isEmpty(),
            "empty model contains no inferred relationships");

        var bases = new ArrayList<Base>();
        var methods = new ArrayList<VirtualMethod>();
        // Exactly the supported admission budget, in reverse encounter order.
        // Small occupied extents are model facts only, not a fabricated Ghidra program.
        for (int order = 65535; order >= 0; order--) {
            bases.add(base(100000, 65536 - order, order));
            methods.add(method(order + 1, order));
        }
        var model = new InheritanceModel(ABI, bases, methods);
        check(model.bases().size() == 65536 && model.virtualMethods().size() == 65536, "inclusive model capacity");
        for (int order = 0; order < 65536; order++) {
            check(model.bases().get(order).baseClassId() == 65536 - order && model.bases().get(order).order() == order,
                "canonical base declaration order preserves identity");
            check(model.virtualMethods().get(order).methodId() == order + 1 &&
                model.virtualMethods().get(order).slot() == order, "canonical method order preserves slot association");
        }
        bases.add(base(200000, 200001, 0));
        rejects(() -> new InheritanceModel(ABI, bases, List.of()), "base model budget");
        methods.add(method(200000, 0));
        rejects(() -> new InheritanceModel(ABI, List.of(), methods), "method model budget");
        bases.clear();
        methods.clear();
        check(model.bases().size() == 65536 && model.virtualMethods().size() == 65536,
            "caller mutation must not erase admitted evidence");
        immutable(() -> model.bases().clear());
        immutable(() -> model.virtualMethods().clear());
    }

    private static VtableEvidence table(long address, int size, long offset) {
        return new VtableEvidence(1, 2, ABI, "_ZTV1D", "vtable for D", address, size, offset, "0".repeat(64), EVIDENCE);
    }

    private static void vtableWitnessRanges() {
        for (int size : new int[] {1, 8, 16, 1024 * 1024}) {
            long start = Long.MAX_VALUE - size;
            var witness = table(start, size, start);
            check(witness.address() == start && witness.fileOffset() == start && witness.byteSize() == size,
                "representable vtable range remains exact");
            check(table(start + 1, size, 0).address() == start + 1, "address crossing bit 63");
            check(table(-((long) size), size, 0).byteSize() == size, "vtable can occupy the last target byte");
            if (size > 1) rejects(() -> table(1L - size, size, 0), "vtable wraps through zero");
            overflow(() -> table(0, size, start + 1), "file offset overflow");
        }
        rejects(() -> table(-1, 16, 0), "wrapping vtable");
        rejects(() -> table(0, 16, -1), "negative file offset");
        for (int size : new int[] {0, -1, 1024 * 1024 + 1, Integer.MAX_VALUE}) {
            rejects(() -> table(0, size, 0), "vtable witness byte budget");
        }
    }

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }

    private static void rejects(Runnable operation, String label) {
        try {
            operation.run();
        }
        catch (IllegalArgumentException expected) {
            checks++;
            return;
        }
        throw new AssertionError("admitted invalid inheritance evidence: " + label);
    }

    private static void overflow(Runnable operation, String label) {
        try {
            operation.run();
        }
        catch (ArithmeticException expected) {
            checks++;
            return;
        }
        throw new AssertionError("wrapped vtable witness: " + label);
    }

    private static void immutable(Runnable operation) {
        try {
            operation.run();
        }
        catch (UnsupportedOperationException expected) {
            checks++;
            return;
        }
        throw new AssertionError("admitted evidence is mutable");
    }
}
