// Controlled evidence/name changes on owned compiler fixtures, never production recovery heuristics.
// @category DWARF.Tests
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonParser;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolType;
import ghidradwarfforge.GhidraClassBindings;
import ghidradwarfforge.GhidraInheritanceBindings;
import ghidradwarfforge.GhidraVtableBindings;
import ghidradwarfforge.GhidraVtableBindings.*;

public class MutateVtableFixture extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (getScriptArgs().length != 3) throw new IllegalArgumentException("variant compiler-model.json witnesses.json");
        String variant = getScriptArgs()[0];
        if (!List.of("missing", "stale", "conflict", "renamed", "qualified", "duplicate").contains(variant)) {
            throw new IllegalArgumentException("unknown fixture mutation");
        }
        var model = JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[1]))).getAsJsonObject();
        var records = JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[2]))).getAsJsonObject().getAsJsonArray("snapshots");
        var before = GhidraInheritanceBindings.read(currentProgram, monitor, this::println);
        if (before.status() != GhidraInheritanceBindings.Status.VALID) throw new AssertionError("missing fixture inheritance");
        var snapshots = new ArrayList<Snapshot>();
        for (var record : records) {
            long id = record.getAsJsonObject().getAsJsonObject("request").get("symbolId").getAsLong();
            var value = GhidraVtableBindings.read(currentProgram, id, monitor, this::println);
            if (value.status() != Status.VALID) throw new AssertionError("missing fixture table");
            snapshots.add(value.snapshot());
        }
        if (variant.equals("renamed") || variant.equals("duplicate")) {
            for (var item : model.getAsJsonArray("classes")) {
                monitor.checkCancelled();
                String original = item.getAsJsonObject().get("name").getAsString();
                var matches = new ArrayList<ghidra.program.model.symbol.Symbol>();
                var candidates = currentProgram.getSymbolTable().getSymbols(original);
                while (candidates.hasNext()) {
                    var candidate = candidates.next();
                    if (candidate.getSymbolType() == SymbolType.CLASS) matches.add(candidate);
                }
                if (matches.size() != 1) throw new AssertionError("ambiguous fixture class " + original);
                var owner = matches.getFirst();
                var binding = GhidraClassBindings.read(currentProgram, owner.getID(), monitor, this::println);
                if (binding.status() != GhidraClassBindings.Status.VALID) throw new AssertionError("missing fixture type");
                String renamed = "Recovered_" + original;
                if (variant.equals("duplicate")) {
                    owner.setName("Shared", SourceType.USER_DEFINED);
                    var parent = currentProgram.getSymbolTable().createNameSpace(owner.getParentNamespace(), original, SourceType.USER_DEFINED);
                    owner.setNamespace(parent);
                    binding.binding().type().setCategoryPath(new CategoryPath("/" + parent.getName(true).replace("::", "/")));
                    renamed = "Shared";
                }
                binding.binding().type().setName(renamed);
                owner.setName(renamed, SourceType.USER_DEFINED);
            }
        }
        for (var snapshot : snapshots) {
            monitor.checkCancelled();
            var request = snapshot.request();
            var symbol = currentProgram.getSymbolTable().getSymbol(request.symbolId());
            switch (variant) {
                case "missing" -> GhidraVtableBindings.remove(currentProgram, request.symbolId(), monitor);
                case "stale" -> {
                    var at = symbol.getAddress().add(request.points().getFirst().tableOffset());
                    currentProgram.getMemory().setByte(at, (byte) (currentProgram.getMemory().getByte(at) ^ 1));
                    if (GhidraVtableBindings.read(currentProgram, request.symbolId(), monitor, ignored -> { }).status() != Status.REJECTED) {
                        throw new AssertionError("stale table accepted");
                    }
                }
                case "conflict" -> {
                    var other = currentProgram.getSymbolTable().createLabel(symbol.getAddress(), "competing_" + symbol.getName(), SourceType.USER_DEFINED);
                    GhidraVtableBindings.save(currentProgram, new Request(other.getID(), request.classId(), request.mangledName(),
                        request.lookupName(), request.byteSize(), request.points(), "explicit conflicting fixture claim"), monitor);
                }
                case "qualified", "duplicate" -> {
                    String original = request.lookupName();
                    String lookup = variant.equals("qualified") ? "origin::" + original : original + "::Shared";
                    String mangled = variant.equals("qualified") ? "_ZTVN6origin" + original.length() + original + "E" :
                        "_ZTVN" + original.length() + original + "6SharedE";
                    // These ASCII fixture spellings are explicit test inputs, not a production mangler.
                    GhidraVtableBindings.save(currentProgram, new Request(request.symbolId(), request.classId(), mangled,
                        lookup, request.byteSize(), request.points(), "explicit qualified fixture linkage identity"), monitor);
                }
                case "renamed" -> {
                    if (!snapshot.equals(GhidraVtableBindings.read(currentProgram, request.symbolId(), monitor, this::println).snapshot())) {
                        throw new AssertionError("coordinated identity-preserving rename invalidated original table witness");
                    }
                }
                default -> throw new AssertionError(variant);
            }
        }
        var after = GhidraInheritanceBindings.read(currentProgram, monitor, this::println);
        if (!before.equals(after)) throw new AssertionError("fixture mutation changed saved inheritance");
        println("vtable-fixture-mutation=PASS variant=" + variant);
    }
}
