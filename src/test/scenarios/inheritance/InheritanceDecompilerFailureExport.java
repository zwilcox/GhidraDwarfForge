// Exercise one actual native decompiler rejection while preserving saved C++ relationships.
// @category DWARF.Tests

import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.script.GhidraScript;
import ghidra.framework.data.DefaultProjectData;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.ProjectLocator;
import ghidra.program.model.listing.Program;
import java.util.Arrays;
import ghidradwarfforge.*;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.nativeapi.*;
import ghidradwarfforge.output.ArtifactPairPublisher;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class InheritanceDecompilerFailureExport extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (currentProgram != null || args.length != 5) throw new IllegalArgumentException("empty host: project-directory project-name output libdwarf libdwarfp");
        var project = new DefaultProjectData(new ProjectLocator(Path.of(args[0]).toRealPath().toString(), args[1]), false, false);
        try {
            var file = project.getFile("/runtime.elf");
            if (file == null || file.isInWritableProject()) throw new AssertionError("fixture must open through a read-only project handle");
            var object = file.getReadOnlyDomainObject(this, DomainFile.DEFAULT_VERSION, monitor);
            try {
                if (!(object instanceof Program program)) throw new AssertionError("fixture is not a program");
                currentProgram = program;
                export(Arrays.copyOfRange(args, 2, args.length));
            }
            finally { currentProgram = null; object.release(this); }
        }
        finally { project.close(); }
    }

    private void export(String[] args) throws Exception {
        Path input = Path.of(currentProgram.getExecutablePath()), output = Path.of(args[0]);
        var elf = ElfImage.read(input);
        var target = DwarfTarget.fromElf(elf);
        long delta = AddressNormalizer.rebaseDelta(currentProgram.getImageBase().getOffset(), GhidraImageBase.originalImageBase(currentProgram));
        var functions = GhidraFunctionSymbols.extractDetailed(currentProgram, monitor, this::println, delta).functions();
        var failures = new ArrayList<String>();
        var decompilation = GhidraSyntheticSource.decompileDetailed(currentProgram, functions, delta, monitor,
            (decompiler, function, timeout, taskMonitor) -> {
                if (!function.getName(true).equals("Diamond::root_value")) return decompiler.decompileFunction(function, timeout, taskMonitor);
                var limited = new DecompileOptions(); limited.setMaxInstructions(1);
                if (!decompiler.setOptions(limited)) throw new AssertionError("cannot set native instruction limit");
                try {
                    var result = decompiler.decompileFunction(function, timeout, taskMonitor);
                    if (result == null || result.decompileCompleted() || !result.getErrorMessage().contains("Flow exceeded maximum allowable instructions")) {
                        throw new AssertionError("expected actual native decompiler instruction-limit rejection");
                    }
                    failures.add(result.getErrorMessage());
                    return result;
                }
                finally {
                    if (!decompiler.setOptions(new DecompileOptions())) throw new AssertionError("cannot restore decompiler options");
                }
            });
        var source = decompilation.source();
        var failed = source.functions().stream().filter(row -> row.failureDiagnostic() != null).toList();
        if (failures.size() != 1 || failed.size() != 1 || !failed.getFirst().name().equals("root_value") ||
                source.functions().stream().noneMatch(row -> row.decompiled() && row.address() > failed.getFirst().address())) {
            throw new AssertionError("native failure was not isolated from later functions");
        }
        var registers = TargetRegisterMap.forElf(target.name(), elf, monitor::isCancelled);
        var extracted = GhidraTypeGraph.extract(currentProgram, functions, registers, delta, monitor, this::println,
            decompilation.recoveredReturns(), decompilation.recoveredParameters(), decompilation.recoveredStatics());
        var model = GhidraCompilerCallPolicy.apply(currentProgram, target, elf, extracted, monitor, this::println);
        if (model.classScopes().inheritance().virtualMethods().size() != 15 || model.functionRelations().thunks().size() != 3) {
            throw new AssertionError("saved independent relationships disappeared before emission");
        }
        Path sourceOutput = Path.of(output + ".c");
        ArtifactPairPublisher.stageAndPublish(output, sourceOutput,
            staged -> new MinimalDwarfSidecarExporter().export(input, staged, Path.of(args[1]), Path.of(args[2]),
                functions, source, model, sourceOutput.getFileName().toString(), monitor::isCancelled, List.of(), this::println),
            source::writeAtomically, monitor::checkCancelled);
        failures.forEach(message -> println("native-decompiler-failure=" + message));
        println("inheritance-decompiler-failure=PASS");
    }
}
