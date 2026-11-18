package ghidradwarfforge.nativeapi;

import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.locations.VariableStorageModel;
import ghidradwarfforge.locations.VariableStorageModel.*;
import ghidradwarfforge.source.SyntheticSourceFile;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.TypeGraph;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/** Actual producer regression for an explicit compiler-fixture memory object, not extraction. */
public final class LocationWidthProducerProbe {
    public static void main(String[] args) throws Exception {
        if (args.length != 8 && args.length != 9) {
            throw new IllegalArgumentException("consumer producer input output address size object split [listed|stable]");
        }
        String mode = args.length == 9 ? args[8] : "listed";
        if (!List.of("listed", "stable", "listed-indirect", "stable-indirect").contains(mode)) {
            throw new IllegalArgumentException("invalid location mode");
        }
        Path consumer = Path.of(args[0]), producer = Path.of(args[1]), input = Path.of(args[2]), output = Path.of(args[3]);
        long address = Long.decode(args[4]), size = Long.decode(args[5]);
        long object = Long.decode(args[6]), split = Long.decode(args[7]);
        if (!(address < split && split < address + size)) throw new AssertionError("split outside compiler function");
        byte[] original = Files.readAllBytes(input);
        var originalIdentity = Files.readAttributes(input, BasicFileAttributes.class);
        var text = SyntheticSourceFile.build("location-width-fixture", "test", List.of(
            new SyntheticSourceFile.FunctionText("forge_location_probe", address,
                "int forge_location_probe(void)\n{\n    return observed;\n}\n", null,
                List.of(new SyntheticSourceFile.RelativeLine(3, List.of(address, split))))));
        Path source = Path.of(output + ".c");
        Files.write(source, text.utf8());
        var functions = List.of(new MinimalDwarfSidecarExporter.FunctionSymbol("forge_location_probe", address, size));
        var exporter = new MinimalDwarfSidecarExporter();
        Storage storage = new MemoryStorage(object);
        if (mode.endsWith("-indirect")) storage = new IndirectMemoryStorage(storage);
        var valid = model(address, size, split, storage, mode);
        try {
            exporter.export(input, output, consumer, producer, functions, text, valid);
        }
        catch (IllegalStateException rejected) {
            throw new AssertionError("valid fixture memory location was rejected", rejected);
        }
        byte[] baseline = Files.readAllBytes(output);
        exporter.export(input, output, consumer, producer, functions, text, valid);
        require(Arrays.equals(baseline, Files.readAllBytes(output)), "valid export not deterministic");
        int failures = 0;
        if (DwarfTarget.fromElf(ElfImage.read(input)).addressBytes() == 4) {
            for (Storage bad : List.of(new MemoryStorage(0x1_0000_0007L),
                    new IndirectMemoryStorage(new MemoryStorage(0x1_0000_0007L)))) {
                for (boolean existing : new boolean[] {true, false}) {
                    if (!existing) Files.delete(output);
                    var before = existing ? Files.readAttributes(output, BasicFileAttributes.class) : null;
                    try {
                        exporter.export(input, output, consumer, producer, functions, text,
                            model(address, size, split, bad, mode));
                        throw new AssertionError("producer accepted a truncated memory location");
                    }
                    catch (IllegalArgumentException expected) {
                        require(expected.getMessage().equals(mode.startsWith("stable")
                            ? "location address exceeds target width" : "location-list value exceeds serialized width"),
                            "wrong rejection");
                        failures++;
                    }
                    catch (IllegalStateException serialized) {
                        throw new AssertionError("oversized location reached native relocation validation", serialized);
                    }
                    require(Files.exists(output) == existing, "failure changed final artifact presence");
                    if (existing) {
                        var after = Files.readAttributes(output, BasicFileAttributes.class);
                        require(Arrays.equals(baseline, Files.readAllBytes(output)), "existing sidecar changed");
                        require(Objects.equals(before.fileKey(), after.fileKey()) &&
                            before.lastModifiedTime().equals(after.lastModifiedTime()), "existing sidecar replaced");
                    }
                    try (var paths = Files.list(output.getParent())) {
                        require(paths.count() == (existing ? 2 : 1), "failed export left staging data");
                    }
                    exporter.export(input, output, consumer, producer, functions, text, valid);
                    require(Arrays.equals(baseline, Files.readAllBytes(output)), "retry differs after rejected overflow");
                }
            }
        }
        require(Arrays.equals(original, Files.readAllBytes(input)), "input bytes changed");
        var after = Files.readAttributes(input, BasicFileAttributes.class);
        require(Objects.equals(originalIdentity.fileKey(), after.fileKey()) &&
            originalIdentity.lastModifiedTime().equals(after.lastModifiedTime()), "input replaced");
        require(Arrays.equals(text.utf8(), Files.readAllBytes(source)), "synthetic source changed");
        System.out.println("location-width-producer=PASS rejected=" + failures + " deterministic=true preserved=true");
    }

    private static ProgramTypeModel model(long start, long size, long split, Storage storage, String mode) {
        var integer = new TypeGraph.TypeRef("integer");
        var graph = new TypeGraph(List.of(new TypeGraph.BaseType("integer", "int", 4, TypeGraph.BaseEncoding.SIGNED)));
        var local = new ProgramTypeModel.LocalVariable("observed", 4, integer, 0, true, "EXPLICIT_COMPILER_FIXTURE");
        var signature = new ProgramTypeModel.FunctionSignature("forge_location_probe", start, integer,
            List.of(), List.of(local), false, false, "default", "EXPLICIT_COMPILER_FIXTURE");
        var evidence = new Evidence(Confidence.USER_DEFINED, "compiler fixture static object symbol");
        var ranges = mode.startsWith("stable") ? List.of(new LocationRange(start, start + size, storage, evidence))
            : List.of(new LocationRange(start, split, storage, evidence),
                new LocationRange(split, start + size, storage, evidence));
        var locations = new VariableStorageModel(List.of(new VariableLocation("forge_location_probe", start,
            "observed", VariableKind.LOCAL, 4, ranges)));
        return new ProgramTypeModel(graph, List.of(signature), List.of(), locations);
    }

    private static void require(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }
}
