package ghidradwarfforge.elf;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.StandardOpenOption;
import java.util.*;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

import ghidradwarfforge.types.ClassScopeModel;
import ghidradwarfforge.types.ClassScopeNames;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.VtableEvidence;

/** Admit table symbols and their type lookup aliases as one original-ELF-backed decision. */
public final class VtableSymbols {
    public record Plan(ProgramTypeModel types, List<ElfLocalObjectSymbol> symbols) {
        public Plan { symbols = List.copyOf(symbols); }
    }
    private VtableSymbols() { }

    public static Plan plan(ElfImage image, ProgramTypeModel model, Set<String> reserved,
            BooleanSupplier cancelled, Consumer<String> diagnostic) throws IOException {
        check(cancelled);
        if (model == null || model.classScopes().vtables().isEmpty()) return new Plan(model, List.of());
        var classes = model.classScopes();
        var tables = classes.vtables();
        if ((long) tables.size() * (model.types().nodes().size() + (long) classes.bindings().size() +
                classes.scopes().size() + tables.size() + model.globals().size()) > 16L * 1024 * 1024) {
            diagnostic.accept("Omitted explicit vtables: canonical lookup comparison budget exceeded");
            return new Plan(withTables(model, List.of()), List.of());
        }
        var names = ClassScopeNames.build(model.types(), classes);
        var occupied = new HashSet<>(reserved);
        for (var function : model.functions()) occupied.add(function.name());
        for (var declaration : model.functionDeclarations()) occupied.add(declaration.name());
        var allocations = new ArrayList<ElfLoadAllocations.Allocation>();
        if (image.sections().isEmpty()) allocations.addAll(ElfLoadAllocations.read(image, cancelled));
        else for (var section : image.sections()) allocations.add(new ElfLoadAllocations.Allocation(section, section.type == 1 ? section.size : 0));
        if ((long) allocations.size() * tables.size() > 16L * 1024 * 1024 ||
                (long) tables.size() * tables.size() > 16L * 1024 * 1024) {
            diagnostic.accept("Omitted explicit vtables: allocation comparison budget exceeded");
            return new Plan(withTables(model, List.of()), List.of());
        }
        var candidates = new LinkedHashMap<VtableEvidence, ElfLocalObjectSymbol>();
        long totalBytes = 0;
        try (var input = FileChannel.open(image.sourcePath(), StandardOpenOption.READ)) {
            image.requireUnchanged(input);
            for (var table : tables) {
                check(cancelled);
                try {
                    require(image.type() == 2 || image.type() == 3, "requires ET_EXEC or ET_DYN");
                    table.abi().requireTarget(image.machine(), image.is64Bit() ? 8 : 4, image.byteOrder());
                    require(!occupied.contains(table.mangledName()) && !occupied.contains(table.lookupName()), "name conflicts with a recovered object or function");
                    for (var global : model.globals()) {
                        check(cancelled);
                        String qualified = global.namespace().isEmpty() ? global.name() :
                            String.join("::", global.namespace()) + "::" + global.name();
                        require(!global.name().equals(table.lookupName()) && !qualified.equals(table.lookupName()),
                            "lookup name conflicts with a recovered global");
                        if (global.name().equals(table.mangledName())) {
                            require(global.namespace().isEmpty() && !global.declaration() &&
                                global.address() == table.address() && global.size() == table.byteSize(),
                                "linkage name conflicts with a different recovered global object");
                        }
                    }
                    require(ClassScopeNames.resolvesTo(model.types(), classes, names, table.classId(), table.lookupName()),
                        "lookup name does not uniquely identify the canonical class");
                    for (var other : tables) {
                        check(cancelled);
                        if (other == table) continue;
                        require(!table.mangledName().equals(other.mangledName()) &&
                            !overlaps(table.address(), table.byteSize(), other.address(), other.byteSize()), "conflicting table identity or overlapping extent");
                    }
                    ElfLoadAllocations.Allocation selected = null;
                    for (var allocation : allocations) {
                        check(cancelled);
                        var section = allocation.section();
                        if ((section.flags & 2) == 0 || !overlaps(table.address(), table.byteSize(), section.address, section.size)) continue;
                        require(selected == null, "overlapping original allocations");
                        selected = allocation;
                    }
                    require(selected != null, "no original allocated storage");
                    var section = selected.section();
                    require((section.flags & 0x400) == 0 && table.address() >= section.address &&
                        table.address() - section.address <= selected.fileSize() &&
                        table.byteSize() <= selected.fileSize() - (table.address() - section.address), "table is not wholly file-backed non-TLS storage");
                    long offset = Math.addExact(section.offset, table.address() - section.address);
                    require(offset == table.fileOffset(), "original ELF mapping disagrees with saved FileBytes");
                    totalBytes += table.byteSize();
                    require(totalBytes <= 64L * 1024 * 1024, "original byte comparison budget exceeded");
                    require(table.originalSha256().equals(FunctionAliasSymbols.hash(input, offset, table.byteSize(), cancelled)),
                        "original ELF bytes disagree with saved evidence");
                    candidates.put(table, new ElfLocalObjectSymbol(table.mangledName(), table.address(), table.byteSize(), section.originalIndex));
                }
                catch (IllegalArgumentException | ArithmeticException invalid) {
                    diagnostic.accept("Omitted explicit vtable " + table.symbolId() + ": " + invalid.getMessage());
                }
            }
            image.requireUnchanged(input);
        }
        final Map<String, MatchedElfSidecarWriter.OriginalObjectMatch> originals;
        try {
            originals = MatchedElfSidecarWriter.originalObjectMatches(image, List.copyOf(candidates.values()), cancelled);
        }
        catch (IllegalArgumentException invalid) {
            diagnostic.accept("Omitted explicit vtables: original symbol identity cannot be established: " + invalid.getMessage());
            return new Plan(withTables(model, List.of()), List.of());
        }
        var accepted = new ArrayList<VtableEvidence>();
        var symbols = new ArrayList<ElfLocalObjectSymbol>();
        for (var entry : candidates.entrySet()) {
            check(cancelled);
            var state = originals.get(entry.getValue().name());
            if (state == MatchedElfSidecarWriter.OriginalObjectMatch.CONFLICT) {
                diagnostic.accept("Omitted explicit vtable " + entry.getKey().symbolId() + ": original ELF symbol has another identity");
                continue;
            }
            accepted.add(entry.getKey());
            if (state == MatchedElfSidecarWriter.OriginalObjectMatch.ABSENT) symbols.add(entry.getValue());
        }
        return new Plan(withTables(model, accepted), symbols);
    }

    private static ProgramTypeModel withTables(ProgramTypeModel model, List<VtableEvidence> tables) {
        var classes = model.classScopes();
        return new ProgramTypeModel(model.types(), model.functions(), model.globals(), model.variableStorage(), model.functionStatics(),
            model.functionDeclarations(), model.lexicalScopes(), new ClassScopeModel(classes.scopes(), classes.bindings(), classes.methods(),
                classes.inheritance(), tables), model.functionRelations());
    }
    private static boolean overlaps(long a, long size, long b, long otherSize) {
        if (size <= 0 || otherSize <= 0) return false;
        return a >= b ? a - b < otherSize : b - a < size;
    }
    private static void require(boolean condition, String reason) {
        if (!condition) throw new IllegalArgumentException(reason);
    }
    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("vtable admission cancelled");
    }
}
