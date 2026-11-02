package ghidradwarfforge.nativeapi;

import java.nio.file.Path;
import java.util.List;

import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel;
import ghidradwarfforge.locations.VariableStorageModel.Confidence;
import ghidradwarfforge.locations.VariableStorageModel.Evidence;
import ghidradwarfforge.locations.VariableStorageModel.IndirectMemoryStorage;
import ghidradwarfforge.locations.VariableStorageModel.LocationRange;
import ghidradwarfforge.locations.VariableStorageModel.VariableKind;
import ghidradwarfforge.locations.VariableStorageModel.VariableLocation;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.ProgramTypeModel.FunctionSignature;
import ghidradwarfforge.types.TypeGraph;
import ghidradwarfforge.types.TypeGraph.BaseEncoding;
import ghidradwarfforge.types.TypeGraph.BaseType;
import ghidradwarfforge.types.TypeGraph.Parameter;
import ghidradwarfforge.types.TypeGraph.TypeRef;

/** Exercise operand-free dereference through both native exprloc and Java loclist encoding. */
public final class IndirectStorageSmoke {
    public static void main(String[] args) throws Exception {
        if (args.length != 4) {
            throw new IllegalArgumentException("expected libdwarf libdwarfp input output");
        }
        Path input = Path.of(args[2]);
        var elf = ElfImage.read(input);
        if (!DwarfTarget.fromElf(elf).name().equals("aarch64")) {
            throw new IllegalArgumentException("indirect smoke requires the AArch64 fixture");
        }
        long address = elf.preferredImageBase() + 0x1000;
        var registers = TargetRegisterMap.forTarget("aarch64");
        var evidence = new Evidence(Confidence.USER_DEFINED, "isolated pointer carrier emission test");
        var scalar = new TypeRef("word");
        var types = new TypeGraph(List.of(new BaseType("word", "long long", 8, BaseEncoding.SIGNED)));
        var signature = new FunctionSignature("indirect", address, scalar,
            List.of(new Parameter("stable", scalar, false), new Parameter("changing", scalar, false)),
            List.of(), false, false, "default", "USER_DEFINED");
        var memory = new IndirectMemoryStorage(registers.registerRelative("sp", 16));
        var stable = new VariableLocation("indirect", address, "stable", VariableKind.PARAMETER, 8,
            List.of(new LocationRange(address, address + 16, memory, evidence)));
        var changing = new VariableLocation("indirect", address, "changing", VariableKind.PARAMETER, 8,
            List.of(new LocationRange(address, address + 4, registers.registerRelative("x0", 0), evidence),
                new LocationRange(address + 4, address + 16, memory, evidence)));
        var model = new ProgramTypeModel(types, List.of(signature), List.of(),
            new VariableStorageModel(List.of(stable, changing)));
        new MinimalDwarfSidecarExporter().export(input, Path.of(args[3]), Path.of(args[0]),
            Path.of(args[1]), List.of(new FunctionSymbol("indirect", address, 16)), null, model);
        System.out.println("indirect-storage-smoke=PASS");
    }
}
