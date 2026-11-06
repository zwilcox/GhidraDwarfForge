package ghidradwarfforge.elf;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.charset.CodingErrorAction;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.Predicate;

import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.TypeGraph;

/** Names already exposed by recovered DWARF or retained ELF symbols, including other frames. */
public final class EquateNameReservations implements Predicate<String> {
    private final Set<String> names;
    private final Set<ByteBuffer> original;

    private EquateNameReservations(Set<String> names, Set<ByteBuffer> original) {
        this.names = Set.copyOf(names);
        this.original = Set.copyOf(original);
    }

    public long size() { return (long) names.size() + original.size(); }

    public Set<String> namedReservations() { return names; }

    public EquateNameReservations withNames(Set<String> additional, BooleanSupplier cancelled) {
        var combined = new HashSet<>(names);
        for (String name : additional) { check(cancelled); add(combined, name); }
        return new EquateNameReservations(combined, original);
    }

    /** Exact UTF-8 spellings only; undecodable names remain reserved byte-for-byte. */
    public List<String> originalSpellings(BooleanSupplier cancelled) {
        var result = new java.util.TreeSet<String>();
        var decoder = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT);
        for (var name : original) {
            check(cancelled);
            try { result.add(decoder.decode(name.asReadOnlyBuffer()).toString()); }
            catch (java.nio.charset.CharacterCodingException invalid) { /* No lossy alias. */ }
        }
        return List.copyOf(result);
    }

    @Override public boolean test(String name) {
        return names.contains(name) || original.contains(ByteBuffer.wrap(name.getBytes(StandardCharsets.UTF_8)));
    }

    public static EquateNameReservations read(ElfImage image, ProgramTypeModel model,
            List<FunctionSymbol> functions, List<ElfFunctionAlias> aliases,
            BooleanSupplier cancelled, Consumer<String> diagnostic) throws IOException {
        var names = new HashSet<String>();
        for (var function : functions) {
            check(cancelled);
            add(names, function.name());
            add(names, function.qualifiedDisplayName());
            for (String part : function.namespacePath()) add(names, part);
        }
        for (var alias : aliases) { check(cancelled); add(names, alias.name()); }
        for (var type : model.types().nodes()) {
            check(cancelled);
            add(names, type.name());
            if (type instanceof TypeGraph.AggregateType aggregate) {
                for (var member : aggregate.members()) { check(cancelled); add(names, member.name()); }
            }
            if (type instanceof TypeGraph.EnumType enumeration) {
                for (var member : enumeration.values()) { check(cancelled); add(names, member.name()); }
            }
            if (type instanceof TypeGraph.SubroutineType routine) {
                for (var parameter : routine.parameters()) { check(cancelled); add(names, parameter.name()); }
            }
        }
        for (var function : model.functions()) {
            check(cancelled);
            add(names, function.name());
            for (var parameter : function.parameters()) { check(cancelled); add(names, parameter.name()); }
            for (var local : function.locals()) { check(cancelled); add(names, local.name()); }
        }
        for (var function : model.functionDeclarations()) {
            check(cancelled);
            add(names, function.name());
            for (var parameter : function.parameters()) { check(cancelled); add(names, parameter.name()); }
        }
        for (var global : model.globals()) {
            check(cancelled);
            add(names, global.name());
            for (var part : global.namespace()) add(names, part);
        }
        for (var variable : model.functionStatics()) { check(cancelled); add(names, variable.name()); }
        for (var scope : model.classScopes().scopes()) { check(cancelled); add(names, scope.name()); }
        for (var method : model.classScopes().methods()) {
            check(cancelled); add(names, method.name()); add(names, method.function().name());
        }
        for (var function : model.lexicalScopes()) {
            check(cancelled);
            for (var local : function.locals()) {
                check(cancelled); add(names, local.savedName()); add(names, local.displayName());
            }
        }
        // Reuse the bounded, byte-exact ELF reader. Inability to establish the
        // retained names fails before publication rather than risking shadowing.
        var original = FunctionAliasSymbols.originalNames(image, cancelled, diagnostic);
        check(cancelled);
        return new EquateNameReservations(names, original);
    }

    private static void add(Set<String> names, String name) {
        if (name == null || name.isEmpty()) return;
        names.add(name);
        for (String part : name.split("::")) if (!part.isEmpty()) names.add(part);
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("equate name reservation cancelled");
    }
}
