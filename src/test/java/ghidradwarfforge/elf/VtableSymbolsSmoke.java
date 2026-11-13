package ghidradwarfforge.elf;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

import ghidradwarfforge.locations.VariableStorageModel;
import ghidradwarfforge.targets.CxxAbiProfile;
import ghidradwarfforge.types.*;
import ghidradwarfforge.types.ClassScopeModel.*;
import ghidradwarfforge.types.TypeGraph.*;

/** Admission must bind bytes, mappings, original identities and exact canonical type lookup. */
public final class VtableSymbolsSmoke {
    private static int checks;
    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("forge-vtable-admission-");
        try {
            for (var abi : List.of(CxxAbiProfile.ITANIUM_X86_64, CxxAbiProfile.ITANIUM_AARCH64)) check(root, abi);
        }
        finally {
            try (var paths = Files.walk(root)) {
                for (var path : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
        System.out.println("vtable-symbols=PASS checks=" + checks);
    }

    private static void check(Path root, CxxAbiProfile abi) throws Exception {
        byte[] bytes = LocalSymbolMergeSmoke.fixture(true, ByteOrder.LITTLE_ENDIAN, false, false);
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).putShort(18, (short) (abi == CxxAbiProfile.ITANIUM_X86_64 ? 62 : 183));
        String hash = hash(Arrays.copyOfRange(bytes, 0x140, 0x158));
        var table = table(abi, 10, 1, "_ZTV1C", "OriginalC", 0x1040, 0x140, hash);
        var model = model(List.of(table), false, false);
        var plan = plan(root, bytes, model, Set.of(), () -> false, new ArrayList<>());
        require(plan.symbols().equals(List.of(new ElfLocalObjectSymbol("_ZTV1C", 0x1040, 24, 1))), "admitted symbol differs");
        require(plan.types().classScopes().vtables().equals(List.of(table)), "admitted witness lost");
        var names = ClassScopeNames.build(plan.types().types(), plan.types().classScopes());
        require(ClassScopeNames.resolvesTo(plan.types().types(), plan.types().classScopes(), names, 1, "OriginalC"), "canonical alias not emitted");
        require(plan.equals(plan(root, bytes, model, Set.of(), () -> false, new ArrayList<>())), "admission not deterministic");
        var matchingGlobal = withGlobal(model, new ProgramTypeModel.GlobalVariable("_ZTV1C", 0x1040, 24,
            new TypeRef("a"), false, "retained table object"));
        require(plan(root, bytes, matchingGlobal, Set.of(), () -> false, new ArrayList<>()).symbols().size() == 1,
            "matching recovered table object blocked admission");
        for (var global : List.of(
                new ProgramTypeModel.GlobalVariable("_ZTV1C", 0x1048, 24, new TypeRef("a"), false, "wrong address"),
                new ProgramTypeModel.GlobalVariable("_ZTV1C", 0x1040, 8, new TypeRef("a"), false, "wrong size"),
                new ProgramTypeModel.GlobalVariable("_ZTV1C", 0x1040, 24, new TypeRef("a"), true, "declaration"),
                new ProgramTypeModel.GlobalVariable("_ZTV1C", 0x1040, 24, new TypeRef("a"), false, "scoped", List.of("other")),
                new ProgramTypeModel.GlobalVariable("OriginalC", 0x1040, 24, new TypeRef("a"), false, "lookup collision"))) {
            reject(root, bytes, withGlobal(model, global), Set.of(), "conflicts");
        }
        reject(root, bytes, model, Set.of("_ZTV1C"), "conflicts");
        reject(root, bytes, model, Set.of("OriginalC"), "conflicts");
        var bad = bytes.clone(); bad[0x140] = 1;
        reject(root, bad, model, Set.of(), "bytes disagree");
        reject(root, bytes, model(List.of(table(abi, 10, 1, "_ZTV1C", "OriginalC", 0x1040, 0x141, hash)), false, false), Set.of(), "mapping disagrees");
        bad = bytes.clone(); LocalSymbolMergeSmoke.field(bad, 1, "flags", 0x406);
        reject(root, bad, model, Set.of(), "non-TLS");
        bad = bytes.clone(); LocalSymbolMergeSmoke.field(bad, 1, "type", 8);
        reject(root, bad, model, Set.of(), "file-backed");
        bad = bytes.clone(); LocalSymbolMergeSmoke.field(bad, 4, "flags", 2); LocalSymbolMergeSmoke.field(bad, 4, "address", 0x1040);
        reject(root, bad, model, Set.of(), "overlapping original");
        bad = bytes.clone(); ByteBuffer.wrap(bad).order(ByteOrder.LITTLE_ENDIAN).putShort(18, (short) 8);
        reject(root, bad, model, Set.of(), "target layout");
        reject(root, bytes, model(List.of(table, table(abi, 11, 1, "_ZTV1C", "OriginalC", 0x1060, 0x160, hash)), false, false), Set.of(), "conflicting table");
        reject(root, bytes, model(List.of(table, table(abi, 11, 2, "_ZTV1D", "OriginalD", 0x1048, 0x148, hash)), false, false), Set.of(), "overlapping extent");
        reject(root, bytes, model(List.of(table), false, true), Set.of(), "canonical class");
        var qualified = table(abi, 10, 1, "_ZTVN1N1CE", "N::C", 0x1040, 0x140, hash);
        plan = plan(root, bytes, model(List.of(qualified), true, false), Set.of(), () -> false, new ArrayList<>());
        require(plan.symbols().size() == 1 && plan.types().classScopes().vtables().size() == 1, "duplicate type names blocked unique lookup");
        reject(root, bytes, withGlobal(model(List.of(qualified), true, false),
            new ProgramTypeModel.GlobalVariable("C", 0x1040, 24, new TypeRef("a"), false,
                "qualified lookup collision", List.of("N"))), Set.of(), "conflicts");
        var ambiguous = table(abi, 10, 1, "_ZTV6Shared", "Shared", 0x1040, 0x140, hash);
        reject(root, bytes, model(List.of(ambiguous), true, false), Set.of(), "canonical class");
        // Reuse an exactly matching original table; never duplicate it in the new symtab.
        bad = bytes.clone();
        Arrays.fill(bad, 0x181, 0x18a, (byte) 0);
        System.arraycopy("_ZTV1C".getBytes(java.nio.charset.StandardCharsets.UTF_8), 0, bad, 0x181, 6);
        var old = ByteBuffer.wrap(bad).order(ByteOrder.LITTLE_ENDIAN);
        old.put(0x218 + 4, (byte) 1); old.putLong(0x218 + 8, 0x1040); old.putLong(0x218 + 16, 24);
        plan = plan(root, bad, model, Set.of(), () -> false, new ArrayList<>());
        require(plan.symbols().isEmpty() && plan.types().classScopes().vtables().size() == 1, "matching original not reused");
        for (int field : List.of(4, 6, 8, 16)) {
            byte[] conflicting = bad.clone(); conflicting[0x218 + field] ^= 1;
            reject(root, conflicting, model, Set.of(), "original ELF symbol");
        }
        byte[] sectionless = bytes.clone();
        var header = ByteBuffer.wrap(sectionless).order(ByteOrder.LITTLE_ENDIAN);
        header.putLong(40, 0); header.putShort(60, (short) 0); header.putShort(62, (short) 0);
        header.putLong(32, 64); header.putShort(54, (short) 56); header.putShort(56, (short) 1);
        header.putInt(64, 1); header.putInt(68, 5); header.putLong(72, 0x100); header.putLong(80, 0x1000);
        header.putLong(96, 128); header.putLong(104, 128); header.putLong(112, 1);
        plan = plan(root, sectionless, model, Set.of(), () -> false, new ArrayList<>());
        require(plan.symbols().equals(List.of(new ElfLocalObjectSymbol("_ZTV1C", 0x1040, 24, 1))), "sectionless allocation mismatch");
        int[] count = {0};
        plan(root, bytes, model, Set.of(), () -> { count[0]++; return false; }, new ArrayList<>());
        for (int stop : List.of(1, count[0] / 2, count[0])) {
            int[] calls = {0};
            try { plan(root, bytes, model, Set.of(), () -> ++calls[0] == stop, new ArrayList<>()); throw new AssertionError("cancellation ignored"); }
            catch (CancellationException expected) { checks++; }
        }
    }

    private static ProgramTypeModel withGlobal(ProgramTypeModel model, ProgramTypeModel.GlobalVariable global) {
        return new ProgramTypeModel(model.types(), model.functions(), List.of(global), model.variableStorage(),
            model.functionStatics(), model.functionDeclarations(), model.lexicalScopes(), model.classScopes());
    }
    private static VtableEvidence table(CxxAbiProfile abi, long id, long owner, String name, String lookup, long address, long offset, String hash) {
        return new VtableEvidence(id, owner, abi, name, lookup, address, 24, offset, hash, "explicit fixture witness");
    }
    private static ProgramTypeModel model(List<VtableEvidence> tables, boolean duplicateNames, boolean occupied) {
        var nodes = new ArrayList<TypeNode>(List.of(new AggregateType("a", duplicateNames ? "Shared" : "CuratedA", 32, AggregateKind.STRUCTURE, List.of()),
            new AggregateType("b", duplicateNames ? "Shared" : "CuratedB", 32, AggregateKind.STRUCTURE, List.of())));
        if (occupied) nodes.add(new AggregateType("foreign", "OriginalC", 64, AggregateKind.STRUCTURE, List.of()));
        var classes = new ClassScopeModel(List.of(new Scope(1, 0, "ScopeA", Kind.CLASS), new Scope(2, 0, "ScopeB", Kind.CLASS)),
            List.of(new Binding(1, new TypeRef("a"), BindingSource.EXPLICIT_SAVED, "saved A"),
                new Binding(2, new TypeRef("b"), BindingSource.EXPLICIT_SAVED, "saved B")), List.of(),
            new InheritanceModel(tables.getFirst().abi(), List.of(), List.of()), tables);
        return new ProgramTypeModel(new TypeGraph(nodes), List.of(), List.of(), new VariableStorageModel(List.of()),
            List.of(), List.of(), List.of(), classes);
    }
    private static VtableSymbols.Plan plan(Path root, byte[] bytes, ProgramTypeModel model, Set<String> reserved,
            BooleanSupplier cancelled, List<String> messages) throws Exception {
        var file = root.resolve("fixture.elf"); Files.write(file, bytes);
        try { return VtableSymbols.plan(ElfImage.read(file), model, reserved, cancelled, messages::add); }
        finally { require(Arrays.equals(bytes, Files.readAllBytes(file)), "admission changed input"); }
    }
    private static void reject(Path root, byte[] bytes, ProgramTypeModel model, Set<String> reserved, String reason) throws Exception {
        var messages = new ArrayList<String>();
        var result = plan(root, bytes, model, reserved, () -> false, messages);
        require(result.symbols().isEmpty() && result.types().classScopes().vtables().isEmpty(), "invalid table admitted: " + messages);
        require(messages.stream().anyMatch(message -> message.contains(reason)), "missing diagnostic " + reason + ": " + messages);
        require(ClassScopeNames.build(result.types().types(), result.types().classScopes()).aliases().stream()
            .noneMatch(alias -> alias.name().equals("OriginalC")), "rejected vtable left its lookup alias");
    }
    private static String hash(byte[] bytes) throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
    private static void require(boolean value, String reason) { checks++; if (!value) throw new AssertionError(reason); }
}
