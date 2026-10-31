// Transform fixture ownership in a disposable read-only session before the production exporter.
// @category DWARF.Tests
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.GhidraLexicalScopes;
import ghidradwarfforge.GhidraStaticBindings;

public class PrepareRecoveredStatics extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String mode = getScriptArgs()[0];
        var bindings = new ArrayList<GhidraStaticBindings.Snapshot>();
        var symbols = currentProgram.getSymbolTable().getAllSymbols(true);
        while (symbols.hasNext()) {
            var symbol = symbols.next();
            if (symbol.getID() <= 0 || symbol.getSymbolType() != ghidra.program.model.symbol.SymbolType.LABEL) continue;
            var result = GhidraStaticBindings.read(currentProgram, symbol.getID(), monitor, this::println);
            if (result.status() == GhidraStaticBindings.Status.VALID) bindings.add(result.binding());
        }
        if (bindings.size() != 5) throw new AssertionError("expected five static identities");
        if (mode.startsWith("inferred")) {
            var binding = bindings.stream().filter(b -> b.owner().getName().equals("other_statics")).findFirst().orElseThrow();
            var label = binding.symbol();
            if (!mode.equals("inferred-stale")) GhidraStaticBindings.remove(currentProgram, label.getID(), monitor);
            label.setName("shadow", SourceType.USER_DEFINED);
            clearListing(label.getAddress(), label.getAddress().add(3));
            if (mode.equals("inferred-namespace")) {
                var namespace = currentProgram.getSymbolTable().createNameSpace(currentProgram.getGlobalNamespace(),
                    "other_statics", SourceType.IMPORTED);
                label.setNamespace(namespace);
            }
            else if (mode.equals("inferred-overlap")) {
                createData(label.getAddress().add(2), ghidra.program.model.data.ShortDataType.dataType);
            }
            else if (mode.equals("inferred-curated")) {
                createData(label.getAddress(), ghidra.program.model.data.UnsignedIntegerDataType.dataType);
            }
            else if (!List.of("inferred", "inferred-stale").contains(mode)) throw new IllegalArgumentException("unknown inferred control");
        }
        else if (List.of("memory", "memory-stale").contains(mode)) {
            var locals = new HashMap<Function, List<GhidraLexicalScopes.Local>>();
            for (var binding : bindings) {
                var label = binding.symbol();
                var address = label.getAddress();
                String name = label.getName();
                GhidraStaticBindings.remove(currentProgram, label.getID(), monitor);
                label.delete();
                clearListing(address, address.add(3));
                var local = binding.owner().addLocalVariable(new LocalVariableImpl(name, 0, IntegerDataType.dataType,
                    address, currentProgram, SourceType.ANALYSIS), SourceType.ANALYSIS);
                locals.computeIfAbsent(binding.owner(), unused -> new ArrayList<>())
                    .add(new GhidraLexicalScopes.Local(local, binding.block(), binding.displayName()));
            }
            for (var item : locals.entrySet()) {
                var prior = GhidraLexicalScopes.read(item.getKey(), monitor, this::println);
                GhidraLexicalScopes.save(item.getKey(), "Fixture saved memory-local identity and lexical visibility",
                    prior.isPresent() ? prior.get().blocks() : List.of(), item.getValue(), monitor);
            }
            if (mode.equals("memory-stale")) {
                var local = locals.entrySet().stream().filter(item -> item.getKey().getName().equals("scoped_statics"))
                    .findFirst().orElseThrow().getValue().getFirst().variable();
                local.setName("changed_after_scope_binding", SourceType.USER_DEFINED);
            }
        }
        else throw new IllegalArgumentException("unknown recovery mode");
        println("static-recovery-preparation=" + mode + " PASS");
    }
}
