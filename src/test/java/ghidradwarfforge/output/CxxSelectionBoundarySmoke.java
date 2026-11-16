package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import ghidradwarfforge.GhidraDeclarationBindings.Binding;
import ghidradwarfforge.GhidraVtableBindings.AddressPoint;
import ghidradwarfforge.GhidraVtableBindings.Request;
import ghidradwarfforge.output.CxxSelection.*;
import ghidradwarfforge.targets.CxxAbiProfile;
import ghidradwarfforge.types.InheritanceModel;
import ghidradwarfforge.types.InheritanceModel.VirtualBase;

/** Bounds and exact analyst identities, without asserting relationships in an actual binary. */
public final class CxxSelectionBoundarySmoke {
    private static final InheritanceModel ABI = new InheritanceModel(CxxAbiProfile.ITANIUM_X86_64, List.of(), List.of());
    private static final Removals EMPTY = new Removals(List.of(), List.of(), List.of());
    private static int checks;

    public static void main(String[] args) throws Exception {
        for (long id : new long[] {0, -1}) {
            reject(() -> new ClassBinding(id, 1, "evidence"));
            reject(() -> new ClassBinding(1, id, "evidence"));
        }
        for (String evidence : new String[] {null, "", " ", "embedded\0nul", "e".repeat(8193)}) {
            reject(() -> new ClassBinding(1, 2, evidence));
        }
        require(new ClassBinding(Long.MAX_VALUE, Long.MAX_VALUE, "e".repeat(8192)).evidence().length() == 8192,
            "exact evidence/identity boundary rejected");
        for (String target : new String[] {null, "", " "}) {
            reject(() -> new CxxSelection(1, target, "gcc", List.of(), List.of(), ABI, List.of(), EMPTY));
            reject(() -> new CxxSelection(1, "lang", target, List.of(), List.of(), ABI, List.of(), EMPTY));
        }
        reject(() -> new CxxSelection(1, "lang", "gcc", List.of(), List.of(), null, List.of(), EMPTY));
        reject(() -> new CxxSelection(1, "lang", "gcc", List.of(), List.of(), InheritanceModel.empty(), List.of(), EMPTY));
        reject(() -> new CxxSelection(1, "lang", "gcc", List.of(), List.of(), ABI, List.of(), null));
        for (List<Long> ids : Arrays.asList(null, List.of(0L), List.of(-1L), List.of(1L, 1L), Arrays.asList(1L, null))) {
            reject(() -> new Removals(ids, List.of(), List.of()));
        }
        var ids = new ArrayList<Long>();
        for (long id = 1; id <= 4096; id++) ids.add(id);
        require(new Removals(ids, List.of(), List.of()).classes().size() == 4096, "exact removal bound rejected");
        ids.add(4097L);
        reject(() -> new Removals(ids, List.of(), List.of()));
        var classes = List.of(new ClassBinding(1, 2, "analyst"));
        var declarations = List.of(new Binding(3, 1, "analyst"));
        var tables = List.of(table(4));
        for (Removals remove : List.of(new Removals(List.of(1L), List.of(), List.of()),
                new Removals(List.of(), List.of(3L), List.of()), new Removals(List.of(), List.of(), List.of(4L)))) {
            reject(() -> new CxxSelection(1, "lang", "gcc", classes, declarations, ABI, tables, remove));
        }
        reject(() -> new CxxSelection(1, "lang", "gcc",
            List.of(new ClassBinding(1, 2, "first"), new ClassBinding(3, 2, "second")), List.of(), ABI, List.of(), EMPTY));
        var budget = new ArrayList<Request>();
        for (long id = 1; id <= 64; id++) budget.add(table(id));
        require(new CxxSelection(1, "lang", "gcc", List.of(), List.of(), ABI, budget, EMPTY).vtables().size() == 64,
            "exact 64 MiB metadata budget rejected");
        budget.add(table(65));
        reject(() -> new CxxSelection(1, "lang", "gcc", List.of(), List.of(), ABI, budget, EMPTY));
        var path = Files.createTempFile("forge-cxx-selection-boundaries-", ".json");
        String valid = """
            {"schema":1,"program_id":"-9223372036854775808","language":"x86:LE:64:default","compiler":"gcc",
             "abi":"ITANIUM_X86_64","inheritance_mode":"replace",
             "classes":[{"class_id":"1","type_id":"9007199254740993","evidence":"analyst type"}],
             "declarations":[{"method_id":"3","class_id":"1","evidence":"addressless method"}],
             "bases":[{"derived_class_id":"1","base_class_id":"2","order":0,"access":"PROTECTED",
              "location":{"kind":"virtual","vptr_offset":"8","slot_offset":"-24"},"evidence":"virtual geometry"}],
             "virtual_methods":[{"method_id":"3","slot":2,"access":"PRIVATE","virtuality":"PURE_VIRTUAL","evidence":"abstract method"}],
             "vtables":[{"symbol_id":"9223372036854775807","class_id":"1","mangled_name":"_ZTV1C",
              "lookup_name":"C::table","byte_size":32,"points":[{"table_offset":16,"subobject_offset":"8","evidence":"secondary"}],
              "evidence":"analyst table"}],"remove":{"classes":[],"declarations":[],"vtables":[]}}
            """;
        try {
            Files.writeString(path, valid);
            byte[] before = Files.readAllBytes(path);
            var actual = CxxSelection.read(path, () -> false);
            require(actual.programId() == Long.MIN_VALUE && actual.classes().getFirst().typeId() == 9007199254740993L &&
                actual.vtables().getFirst().symbolId() == Long.MAX_VALUE, "decimal identity was rounded or truncated");
            require(actual.inheritance().bases().getFirst().location().equals(new VirtualBase(8, -24)), "virtual geometry lost");
            var method = actual.inheritance().virtualMethods().getFirst();
            require(method.slot() == 2 && method.access() == InheritanceModel.Access.PRIVATE &&
                method.virtuality() == InheritanceModel.Virtuality.PURE_VIRTUAL, "abstract method selection changed");
            var selected = actual.vtables().getFirst();
            require(selected.byteSize() == 32 && selected.lookupName().equals("C::table") &&
                selected.points().equals(List.of(new AddressPoint(16, 8, "secondary"))), "vtable address point changed");
            require(Arrays.equals(before, Files.readAllBytes(path)), "selection read changed the input file");
            for (String bad : List.of(valid.replace("\"slot\":2", "\"slot\":2147483648"),
                    valid.replace("\"table_offset\":16", "\"table_offset\":-1"),
                    valid.replace("\"kind\":\"virtual\"", "\"kind\":\"unknown\""),
                    valid.replace("\"slot_offset\":\"-24\"", "\"slot_offset\":\"-24\",\"offset\":\"0\""))) {
                Files.writeString(path, bad);
                try { CxxSelection.read(path, () -> false); throw new AssertionError("invalid C++ geometry accepted"); }
                catch (IOException expected) { checks++; }
            }
        }
        finally { Files.delete(path); }
        System.out.println("cxx-selection-boundaries=PASS checks=" + checks);
    }

    private static Request table(long id) {
        return new Request(id, 1, "_ZTV1C", "C::table", 1024 * 1024, List.of(new AddressPoint(16, 0, "point")), "table");
    }
    @FunctionalInterface private interface Action { void run() throws Exception; }
    private static void reject(Action action) throws Exception {
        try { action.run(); throw new AssertionError("invalid C++ selection accepted"); }
        catch (IllegalArgumentException expected) { checks++; }
    }
    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }
}
