package ghidradwarfforge.types;

import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

import ghidradwarfforge.targets.CxxAbiProfile;
import ghidradwarfforge.types.ClassScopeModel.*;
import ghidradwarfforge.types.InheritanceModel.*;
import ghidradwarfforge.types.TypeGraph.*;

/** Identity and graph admission; runtime validation is separate from this model test. */
public final class InheritanceModelSmoke {
    private static int checks;
    private static final String EVIDENCE = "explicit fixture layout";
    private static final List<Scope> SCOPES = List.of(new Scope(1, 0, "Same", Kind.CLASS),
        new Scope(2, 0, "Same", Kind.CLASS), new Scope(3, 0, "Same", Kind.CLASS), new Scope(4, 0, "Same", Kind.CLASS));
    private static final List<Binding> BINDINGS = SCOPES.stream().map(s ->
        new Binding(s.id(), new TypeRef("class" + s.id()), BindingSource.EXPLICIT_SAVED, EVIDENCE)).toList();
    private static final List<Method> METHODS = List.of(
        new Method(101, 4, "inspect", FunctionReference.definition("inspect", 0x1000)),
        new Method(102, 4, "other", FunctionReference.definition("other", 0x1100)));
    private static final TypeGraph TYPES = new TypeGraph(List.of(
        new BaseType("int", "int", 4, BaseEncoding.SIGNED),
        new AggregateType("class1", "Same", 16, AggregateKind.STRUCTURE, List.of()),
        new AggregateType("class2", "Same", 32, AggregateKind.STRUCTURE, List.of()),
        new AggregateType("class3", "Same", 32, AggregateKind.STRUCTURE, List.of()),
        new AggregateType("class4", "Same", 48, AggregateKind.STRUCTURE, List.of()),
        new IndirectionType("pointer4", "Same *", 8, IndirectionKind.POINTER, new TypeRef("class4"))));

    private static Base base(long derived, long parent, int order, BaseLocation location) {
        return new Base(derived, parent, order, Access.PUBLIC, location, EVIDENCE);
    }

    private static VirtualMethod method(long id, int slot) {
        return new VirtualMethod(id, slot, Access.PUBLIC, Virtuality.VIRTUAL, EVIDENCE);
    }

    private static List<ProgramTypeModel.FunctionSignature> signatures(boolean object) {
        return METHODS.stream().map(m -> new ProgramTypeModel.FunctionSignature(m.name(), m.function().address(),
            new TypeRef("int"), object ? List.of(new Parameter("receiver", new TypeRef("pointer4"), true, false, true)) :
                List.<Parameter>of(), List.of(), false, false, "default", "USER_DEFINED")).toList();
    }

    private static void validate(InheritanceModel model, List<Binding> bindings, boolean object) {
        var scopes = new ClassScopeModel(SCOPES, bindings, METHODS, model);
        scopes.validate(TYPES, signatures(object), List.of());
        check(scopes.inheritance().equals(model), "inheritance model retained");
    }

    public static void main(String[] args) {
        var bases = List.of(base(2, 1, 0, new VirtualBase(0, -24)), base(3, 1, 0, new VirtualBase(0, -24)),
            base(4, 2, 0, new FixedBase(0, 16)), base(4, 3, 1, new FixedBase(16, 16)));
        var virtuals = List.of(method(101, 0), method(102, 1));
        for (var abi : List.of(CxxAbiProfile.ITANIUM_X86_64, CxxAbiProfile.ITANIUM_AARCH64)) {
            var model = new InheritanceModel(abi, bases, virtuals);
            validate(model, BINDINGS, true);
            for (int seed = 0; seed < 12; seed++) {
                var shuffled = new ArrayList<>(bases);
                Collections.shuffle(shuffled, new Random(seed));
                check(new InheritanceModel(abi, shuffled, virtuals.reversed()).equals(model), "deterministic declaration order");
            }
            // Full base sizes overlap; occupied extents can reuse padding or be empty.
            validate(new InheritanceModel(abi, List.of(base(4, 2, 0, new FixedBase(32, 16)),
                base(4, 3, 1, new FixedBase(32, 0))), virtuals), BINDINGS, true);
            validate(new InheritanceModel(abi, List.of(base(4, 1, 0, new VirtualBase(16, -32))),
                List.of(new VirtualMethod(101, 4, Access.PROTECTED, Virtuality.PURE_VIRTUAL, EVIDENCE))), BINDINGS, true);
            rejects(() -> new InheritanceModel(abi, List.of(bases.getFirst(), bases.getFirst()), List.of()), "duplicate direct base");
            rejects(() -> new InheritanceModel(abi, List.of(base(4, 2, 0, new FixedBase(0, 16)),
                base(4, 3, 0, new FixedBase(16, 16))), List.of()), "duplicate direct base");
            rejects(() -> new InheritanceModel(abi, List.of(base(4, 2, 1, new FixedBase(0, 16))), List.of()), "missing base declaration order");
            rejects(() -> new InheritanceModel(abi, List.of(base(1, 2, 0, new FixedBase(0, 1)),
                base(2, 1, 0, new FixedBase(0, 1))), List.of()), "cyclic inheritance");
            for (BaseLocation bad : List.of(new FixedBase(48, 0), new FixedBase(32, 17),
                    new FixedBase(0, 33), new FixedBase(Long.MAX_VALUE, Long.MAX_VALUE),
                    new VirtualBase(41, -24), new VirtualBase(0, -8), new VirtualBase(0, -25))) {
                rejects(() -> validate(new InheritanceModel(abi, List.of(base(4, 2, 0, bad)), List.of()), BINDINGS, true),
                    bad instanceof FixedBase ? "base subobject exceeds" : "invalid virtual-base");
            }
            rejects(() -> validate(new InheritanceModel(abi, List.of(base(4, 99, 0, new FixedBase(0, 1))), List.of()),
                BINDINGS, true), "explicit saved class layout");
            var inferred = new ArrayList<>(BINDINGS);
            inferred.set(3, new Binding(4, new TypeRef("class4"), BindingSource.CURRENT_AUTO_THIS, EVIDENCE));
            rejects(() -> validate(model, inferred, true), "explicit saved class layout");
            rejects(() -> validate(model, BINDINGS, false), "validated object parameter");
            rejects(() -> validate(new InheritanceModel(abi, bases, List.of(method(999, 0))), BINDINGS, true),
                "virtual method identity is not present");
            rejects(() -> validate(new InheritanceModel(abi, bases, List.of(method(101, 0), method(102, 0))), BINDINGS, true),
                "conflicting virtual slot");
            rejects(() -> new InheritanceModel(abi, bases, List.of(method(101, 0), method(101, 1))), "duplicate virtual method");
            var deep = new ArrayList<Base>();
            for (int id = 1; id <= 8192; id++) deep.add(base(id + 1, id, 0, new FixedBase(0, 1)));
            check(new InheritanceModel(abi, deep, List.of()).bases().size() == 8192, "deep acyclic model avoids recursion");
            deep.add(base(1, 8193, 0, new FixedBase(0, 1)));
            rejects(() -> new InheritanceModel(abi, deep, List.of()), "cyclic inheritance");
        }
        check(new ClassScopeModel(SCOPES, BINDINGS, METHODS).inheritance().equals(InheritanceModel.empty()), "no inferred inheritance");
        rejects(() -> new InheritanceModel(CxxAbiProfile.UNSPECIFIED, bases, virtuals), "unspecified ABI");
        rejects(() -> new Base(1, 1, 0, Access.PRIVATE, new FixedBase(0, 1), EVIDENCE), "base identity");
        rejects(() -> new Base(2, 1, 0, Access.PUBLIC, new FixedBase(0, 1), " "), "bounded provenance");
        rejects(() -> new VirtualMethod(101, 0, Access.PUBLIC, Virtuality.VIRTUAL, "bad\0text"), "bounded provenance");
        rejects(() -> new FixedBase(-1, 1), "negative fixed base");
        rejects(() -> new VirtualBase(0, 0), "invalid virtual base");
        CxxAbiProfile.ITANIUM_X86_64.requireTarget(62, 8, ByteOrder.LITTLE_ENDIAN);
        CxxAbiProfile.ITANIUM_AARCH64.requireTarget(183, 8, ByteOrder.LITTLE_ENDIAN);
        checks += 2;
        rejects(() -> CxxAbiProfile.ITANIUM_X86_64.requireTarget(183, 8, ByteOrder.LITTLE_ENDIAN), "does not match");
        rejects(() -> CxxAbiProfile.ITANIUM_AARCH64.requireTarget(183, 4, ByteOrder.LITTLE_ENDIAN), "does not match");
        rejects(() -> CxxAbiProfile.ITANIUM_AARCH64.requireTarget(183, 8, ByteOrder.BIG_ENDIAN), "does not match");
        System.out.println("inheritance-model=PASS checks=" + checks);
    }

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }

    private static void rejects(Runnable operation, String fragment) {
        try {
            operation.run();
            throw new AssertionError("accepted invalid model: " + fragment);
        }
        catch (IllegalArgumentException expected) {
            check(expected.getMessage().contains(fragment), "wrong rejection: " + expected.getMessage());
        }
    }
}
