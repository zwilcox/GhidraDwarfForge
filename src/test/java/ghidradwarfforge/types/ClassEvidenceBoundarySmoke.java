package ghidradwarfforge.types;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Random;

import ghidradwarfforge.targets.CxxAbiProfile;
import ghidradwarfforge.types.ClassScopeModel.*;
import ghidradwarfforge.types.TypeGraph.TypeRef;

/** Saved evidence admission only; ELF identity and debugger admission are separate checks. */
public final class ClassEvidenceBoundarySmoke {
    private static int checks;
    private static final CxxAbiProfile ABI = CxxAbiProfile.ITANIUM_X86_64;
    private static final String HASH = "0123456789abcdef".repeat(4);
    private static final List<Scope> SCOPES = List.of(new Scope(1, 0, "Object", Kind.CLASS),
        new Scope(2, 0, "Other", Kind.CLASS));

    public static void main(String[] args) {
        identities();
        tableFields();
        ownership();
        System.out.println("class-evidence-boundaries=PASS checks=" + checks);
    }

    private static void identities() {
        for (long id : new long[] {-1, 0}) {
            reject(() -> new Scope(id, 0, "Object", Kind.CLASS), "scope ID");
            reject(() -> new Binding(id, new TypeRef("object"), BindingSource.EXPLICIT_SAVED, "saved"), "binding ID");
            reject(() -> new Method(id, 1, "method", FunctionReference.definition("method", 0)), "method ID");
            reject(() -> new Method(3, id, "method", FunctionReference.definition("method", 0)), "method owner");
        }
        reject(() -> new Scope(1, -1, "Object", Kind.CLASS), "negative parent");
        reject(() -> new Scope(1, 0, "Object", null), "missing kind");
        reject(() -> new Binding(1, null, BindingSource.EXPLICIT_SAVED, "saved"), "missing type");
        reject(() -> new Binding(1, new TypeRef("object"), null, "saved"), "missing binding source");
        reject(() -> new Method(3, 1, "method", null), "missing method target");
        for (String text : new String[] {null, "", " \t\n", "bad\0text"}) {
            reject(() -> new Scope(1, 0, text, Kind.CLASS), "scope text");
            reject(() -> new Binding(1, new TypeRef("object"), BindingSource.EXPLICIT_SAVED, text), "binding evidence");
            reject(() -> new Method(3, 1, text, FunctionReference.definition("method", 0)), "method name");
            reject(() -> FunctionReference.definition(text, 0), "function name");
        }
        reject(() -> new FunctionReference("method", -1, null), "missing declaration key");
        reject(() -> FunctionReference.declaration("method", " "), "blank declaration key");
        reject(() -> FunctionReference.declaration("method", ""), "declaration without key");
        require(FunctionReference.definition("method", Long.MAX_VALUE).address() == Long.MAX_VALUE,
            "valid image address was narrowed");
        reject(() -> new ClassScopeModel(null, List.of(), List.of()), "missing scopes");
        reject(() -> new ClassScopeModel(SCOPES, null, List.of()), "missing bindings");
        reject(() -> new ClassScopeModel(SCOPES, List.of(), null), "missing methods");
        reject(() -> new ClassScopeModel(SCOPES, List.of(), List.of(), null), "missing inheritance");
        reject(() -> model(List.of(), null, ABI), "missing tables");
        reject(() -> new ClassScopeModel(Arrays.asList((Scope) null), List.of(), List.of()), "null scope");
        reject(() -> new ClassScopeModel(SCOPES, Arrays.asList((Binding) null), List.of()), "null binding");
        reject(() -> new ClassScopeModel(SCOPES, List.of(), Arrays.asList((Method) null)), "null method");
    }

    private static VtableEvidence table(long symbol, long owner, CxxAbiProfile abi, String mangled,
            String lookup, long address, int size, long offset, String hash, String provenance) {
        return new VtableEvidence(symbol, owner, abi, mangled, lookup, address, size, offset, hash, provenance);
    }

    private static VtableEvidence table(long symbol, long owner, CxxAbiProfile abi) {
        return table(symbol, owner, abi, "_ZTV6Object", "vtable for Object", 0x1000, 24, 128, HASH, "saved analyst table");
    }

    private static void tableFields() {
        for (long bad : new long[] {-1, 0}) {
            reject(() -> table(bad, 1, ABI), "table symbol");
            reject(() -> table(100, bad, ABI), "table owner");
        }
        for (var abi : new CxxAbiProfile[] {null, CxxAbiProfile.UNSPECIFIED}) {
            reject(() -> table(100, 1, abi), "table ABI");
        }
        for (String name : new String[] {null, "", "_ZTI6Object", "_ZTV" + "a".repeat(8189), "_ZTVbad\0name"}) {
            reject(() -> table(100, 1, ABI, name, "Object", 0, 1, 0, HASH, "saved"), "mangled name");
        }
        for (String name : new String[] {null, "", " \n", "a".repeat(8193), "bad\0name"}) {
            reject(() -> table(100, 1, ABI, "_ZTV6Object", name, 0, 1, 0, HASH, "saved"), "lookup name");
        }
        for (String provenance : new String[] {null, "", " \n", "a".repeat(8193)}) {
            reject(() -> table(100, 1, ABI, "_ZTV6Object", "Object", 0, 1, 0, HASH, provenance), "provenance");
        }
        for (String hash : new String[] {null, "", "0".repeat(63), "0".repeat(65), HASH.toUpperCase(), "g".repeat(64)}) {
            reject(() -> table(100, 1, ABI, "_ZTV6Object", "Object", 0, 1, 0, hash, "saved"), "content hash");
        }
        for (int size : new int[] {-1, 0, 1048577}) {
            reject(() -> table(100, 1, ABI, "_ZTV6Object", "Object", 0, size, 0, HASH, "saved"), "byte extent");
        }
        reject(() -> table(100, 1, ABI, "_ZTV6Object", "Object", -1, 1, 0, HASH, "saved"), "negative address");
        reject(() -> table(100, 1, ABI, "_ZTV6Object", "Object", 0, 1, -1, HASH, "saved"), "negative offset");
        for (var abi : List.of(ABI, CxxAbiProfile.ITANIUM_AARCH64)) {
            for (int size : new int[] {1, 24, 1048576}) {
                long end = Long.MAX_VALUE - size;
                var accepted = table(100, 1, abi, "_ZTV" + "a".repeat(8188), "b".repeat(8192),
                    end, size, end, HASH, "c".repeat(8192));
                require(accepted.address() + accepted.byteSize() == Long.MAX_VALUE &&
                    accepted.fileOffset() + accepted.byteSize() == Long.MAX_VALUE,
                    "valid boundary extent changed");
                overflow(() -> table(100, 1, abi, "_ZTV6Object", "Object", end + 1, size, 0, HASH, "saved"));
                overflow(() -> table(100, 1, abi, "_ZTV6Object", "Object", 0, size, end + 1, HASH, "saved"));
            }
        }
    }

    private static Binding binding(long owner, BindingSource source) {
        return new Binding(owner, new TypeRef("type-" + owner), source, "saved binding");
    }

    private static ClassScopeModel model(List<Binding> bindings, List<VtableEvidence> tables, CxxAbiProfile abi) {
        return new ClassScopeModel(SCOPES, bindings, List.of(), new InheritanceModel(abi, List.of(), List.of()), tables);
    }

    private static void ownership() {
        var saved = binding(1, BindingSource.EXPLICIT_SAVED);
        reject(() -> model(List.of(saved), Arrays.asList((VtableEvidence) null), ABI), "null table");
        // Cross all owner/source/ABI choices. Only matching explicit ownership establishes a table.
        for (var source : BindingSource.values()) {
            for (long owner : new long[] {1, 2, 3}) {
                for (var tableAbi : List.of(ABI, CxxAbiProfile.ITANIUM_AARCH64)) {
                    var bindings = List.of(binding(1, source), binding(2, BindingSource.CURRENT_AUTO_THIS));
                    var tables = List.of(table(100, owner, tableAbi));
                    if (owner == 1 && source == BindingSource.EXPLICIT_SAVED && tableAbi == ABI) {
                        require(model(bindings, tables, ABI).vtables().equals(tables), "explicit table lost");
                    }
                    else reject(() -> model(bindings, tables, ABI), "unproven vtable ownership accepted");
                }
            }
        }
        reject(() -> model(List.of(), List.of(table(100, 1, ABI)), ABI), "table without binding");
        reject(() -> model(List.of(saved), List.of(table(100, 1, ABI), table(100, 1, ABI)), ABI), "duplicate table symbol");
        var expected = List.of(
            table(102, 1, ABI, "_ZTV1A", "A", 16, 8, 0, HASH, "saved"),
            table(103, 1, ABI, "_ZTV1A", "A", 16, 8, 0, HASH, "saved"),
            table(101, 1, ABI, "_ZTV1B", "B", 16, 8, 0, HASH, "saved"),
            table(104, 1, ABI, "_ZTV1A", "A", 32, 8, 0, HASH, "saved"));
        for (int seed = 0; seed < 24; seed++) {
            var input = new ArrayList<>(expected);
            Collections.shuffle(input, new Random(seed));
            var model = model(List.of(saved), input, ABI);
            input.clear();
            require(model.vtables().equals(expected), "vtable ordering or snapshot changed");
            try { model.vtables().clear(); throw new AssertionError("mutable vtable snapshot"); }
            catch (UnsupportedOperationException correct) { checks++; }
        }
        var limit = new ArrayList<VtableEvidence>();
        for (int index = 0; index < 4096; index++) limit.add(table(100 + index, 1, ABI));
        require(model(List.of(saved), limit, ABI).vtables().size() == 4096, "valid table budget refused");
        limit.add(table(4196, 1, ABI));
        reject(() -> model(List.of(saved), limit, ABI), "excess table budget");
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }

    private static void reject(Runnable operation, String message) {
        checks++;
        try { operation.run(); }
        catch (IllegalArgumentException expected) { return; }
        throw new AssertionError("invalid class evidence accepted: " + message);
    }

    private static void overflow(Runnable operation) {
        checks++;
        try { operation.run(); }
        catch (ArithmeticException expected) { return; }
        throw new AssertionError("overflowing table extent accepted");
    }
}
