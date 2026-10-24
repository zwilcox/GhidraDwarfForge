package ghidradwarfforge.nativeapi;

import java.nio.file.Path;
import java.util.List;

import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel;
import ghidradwarfforge.locations.VariableStorageModel.Confidence;
import ghidradwarfforge.locations.VariableStorageModel.Evidence;
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

/** Isolated native emission of a scalar in the upper half of a canonical ARM D register. */
public final class FloatingRegisterSliceSmoke {
    public static void main(String[] args) throws Exception {
        if (args.length != 4) {
            throw new IllegalArgumentException(
                "usage: FloatingRegisterSliceSmoke <libdwarf> <libdwarfp> <ARM ELF> <output>");
        }
        Path input = Path.of(args[2]);
        var elf = ElfImage.read(input);
        if (!DwarfTarget.fromElf(elf).name().equals("arm")) {
            throw new IllegalArgumentException("slice smoke requires the ARM32 target");
        }
        long address = elf.preferredImageBase() + 0x1000;
        TypeRef scalar = new TypeRef("float");
        var types = new TypeGraph(List.of(new BaseType("float", "float", 4, BaseEncoding.FLOAT)));
        var signature = new FunctionSignature("scalar_slice", address, scalar,
            List.of(new Parameter("upper_float", scalar, false)), List.of(),
            false, false, "default", "USER_DEFINED");
        var location = new VariableLocation("scalar_slice", address, "upper_float",
            VariableKind.PARAMETER, 4, List.of(new LocationRange(address, address + 16,
                TargetRegisterMap.forTarget("arm").register("d0", 32, 32),
                new Evidence(Confidence.USER_DEFINED, "isolated scalar slice producer smoke"))));
        var model = new ProgramTypeModel(types, List.of(signature), List.of(),
            new VariableStorageModel(List.of(location)));
        new MinimalDwarfSidecarExporter().export(input, Path.of(args[3]), Path.of(args[0]),
            Path.of(args[1]), List.of(new FunctionSymbol("scalar_slice", address, 16)),
            null, model);
        System.out.println("floating-register-slice-smoke=PASS");
    }
}
