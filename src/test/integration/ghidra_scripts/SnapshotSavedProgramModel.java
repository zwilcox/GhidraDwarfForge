// Fingerprint the extraction model independently of native DWARF serialization.
// @category DWARF.Tests

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.script.GhidraScript;
import ghidradwarfforge.AddressNormalizer;
import ghidradwarfforge.GhidraFunctionSymbols;
import ghidradwarfforge.GhidraImageBase;
import ghidradwarfforge.GhidraSyntheticSource;
import ghidradwarfforge.GhidraTypeGraph;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.nativeapi.DwarfTarget;

public class SnapshotSavedProgramModel extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) {
            throw new IllegalArgumentException("expected input ELF and output prefix");
        }
        long delta = AddressNormalizer.rebaseDelta(
            currentProgram.getImageBase().getOffset(),
            GhidraImageBase.originalImageBase(currentProgram));
        var target = DwarfTarget.fromElf(ElfImage.read(Path.of(args[0])));
        List<String> diagnostics = new ArrayList<>();
        var extraction = GhidraFunctionSymbols.extractDetailed(currentProgram, monitor,
            diagnostics::add, delta);
        var source = GhidraSyntheticSource.decompile(currentProgram,
            extraction.functions(), delta, monitor);
        var model = GhidraTypeGraph.extract(currentProgram, extraction.functions(),
            target.name(), delta, monitor, diagnostics::add);
        List<String> raw = new ArrayList<>();
        Map<String, String> names = new HashMap<>();
        for (var type : model.types().nodes()) {
            String label = type.getClass().getSimpleName() + ":" + type.name() +
                ":" + type.byteSize();
            if (names.containsValue(label)) {
                throw new AssertionError("ambiguous fixture normalization: " + label);
            }
            names.put(type.key(), label);
            raw.add("TYPE " + type);
        }
        if (!names.containsValue("OpaqueType:undefined:1")) {
            throw new AssertionError("fixture must reach the generic undefined singleton");
        }
        for (String label : List.of("AggregateType:saved_identity_type:4",
                "AggregateType:Elf64_Dyn:16")) {
            if (names.entrySet().stream().noneMatch(entry ->
                    entry.getValue().equals(label) && entry.getKey().startsWith("uid:"))) {
                throw new AssertionError("missing persisted analyst/imported identity: " + label);
            }
        }
        model.functions().forEach(value -> raw.add("FUNCTION " + value));
        model.globals().forEach(value -> raw.add("GLOBAL " + value));
        model.functionStatics().forEach(value -> raw.add("STATIC " + value));
        model.variableStorage().variables().forEach(value -> raw.add("LOCATION " + value));
        extraction.functions().forEach(value -> raw.add("BODY " + value));
        extraction.skippedFunctions().forEach(value -> raw.add("SKIPPED " + value));
        diagnostics.forEach(value -> raw.add("DIAGNOSTIC " + value));
        Files.write(Path.of(args[1] + ".raw.txt"), raw);
        List<String> keys = names.keySet().stream()
            .sorted(Comparator.comparingInt(String::length).reversed()).toList();
        List<String> normalized = new ArrayList<>();
        for (String line : raw) {
            for (String key : keys) {
                line = line.replace(key, names.get(key));
            }
            normalized.add(line);
        }
        normalized.sort(String::compareTo);
        Files.write(Path.of(args[1] + ".semantic.txt"), normalized);
        source.writeAtomically(Path.of(args[1] + ".source.c"));
        println("saved-program-model-snapshot=" + args[1]);
    }
}
