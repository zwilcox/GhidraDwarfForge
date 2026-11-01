// Exercise an actual native decompiler instruction-limit failure with saved scopes.
// @category DWARF.Tests
import java.nio.file.Path;
import java.util.ArrayList;

import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.script.GhidraScript;
import ghidradwarfforge.AddressNormalizer;
import ghidradwarfforge.GhidraCompilerCallPolicy;
import ghidradwarfforge.GhidraFunctionSymbols;
import ghidradwarfforge.GhidraImageBase;
import ghidradwarfforge.GhidraSyntheticSource;
import ghidradwarfforge.GhidraTypeGraph;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.nativeapi.DwarfTarget;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter;
import ghidradwarfforge.nativeapi.PackagedNativeLibraries;
import ghidradwarfforge.output.ArtifactPairPublisher;

public class LexicalDecompilerFailureExport extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (getScriptArgs().length != 1) throw new IllegalArgumentException("output");
        Path input = Path.of(currentProgram.getExecutablePath());
        Path output = Path.of(getScriptArgs()[0]);
        var elf = ElfImage.read(input);
        var target = DwarfTarget.fromElf(elf);
        var natives = PackagedNativeLibraries.resolve();
        long delta = AddressNormalizer.rebaseDelta(currentProgram.getImageBase().getOffset(),
            GhidraImageBase.originalImageBase(currentProgram));
        var functions = GhidraFunctionSymbols.extractDetailed(currentProgram, monitor, this::println, delta).functions();
        var failures = new ArrayList<String>();
        var decompilation = GhidraSyntheticSource.decompileDetailed(currentProgram, functions, delta, monitor,
            (decompiler, function, timeout, taskMonitor) -> {
                if (!function.getName().equals("scoped")) return decompiler.decompileFunction(function, timeout, taskMonitor);
                var limited = new DecompileOptions();
                limited.setMaxInstructions(1);
                if (!decompiler.setOptions(limited)) throw new AssertionError("cannot set instruction limit");
                try {
                    var result = decompiler.decompileFunction(function, timeout, taskMonitor);
                    if (result == null || result.decompileCompleted() || result.getErrorMessage().isBlank()) {
                        throw new AssertionError("expected actual decompiler rejection");
                    }
                    failures.add(result.getErrorMessage());
                    return result;
                }
                finally {
                    if (!decompiler.setOptions(new DecompileOptions())) throw new AssertionError("cannot restore decompiler options");
                }
            });
        var source = decompilation.source();
        var failed = source.functions().stream().filter(f -> f.name().equals("scoped")).findFirst().orElseThrow();
        if (failures.size() != 1 || failed.decompiled() || source.functions().stream().filter(f -> !f.decompiled()).count() != 1 ||
                source.functions().stream().noneMatch(f -> f.address() > failed.address() && f.decompiled())) {
            throw new AssertionError("decompiler failure was not isolated");
        }
        var registers = TargetRegisterMap.forElf(target.name(), elf, monitor::isCancelled);
        var extracted = GhidraTypeGraph.extract(currentProgram, functions, registers, delta, monitor, this::println,
            decompilation.recoveredReturns(), decompilation.recoveredParameters(), decompilation.recoveredStatics());
        var model = GhidraCompilerCallPolicy.apply(currentProgram, target, elf, extracted, monitor, this::println);
        if (model.lexicalScopes().size() != 1) throw new AssertionError("scope evidence unexpectedly removed before emission");
        Path sourceOutput = Path.of(output + ".c");
        ArtifactPairPublisher.stageAndPublish(output, sourceOutput,
            staged -> new MinimalDwarfSidecarExporter().export(input, staged, natives.consumer(), natives.producer(),
                functions, source, model, sourceOutput.getFileName().toString()),
            source::writeAtomically, monitor::checkCancelled);
        failures.forEach(message -> println("native-decompiler-failure=" + message));
        println("lexical-decompiler-failure=PASS");
    }
}
