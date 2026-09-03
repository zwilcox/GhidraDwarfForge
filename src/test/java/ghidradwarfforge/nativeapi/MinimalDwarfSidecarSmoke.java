package ghidradwarfforge.nativeapi;

import java.nio.file.Path;
import java.util.List;

import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel;
import ghidradwarfforge.locations.VariableStorageModel.Confidence;
import ghidradwarfforge.locations.VariableStorageModel.Evidence;
import ghidradwarfforge.locations.VariableStorageModel.LocationRange;
import ghidradwarfforge.locations.VariableStorageModel.VariableKind;
import ghidradwarfforge.locations.VariableStorageModel.VariableLocation;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.source.SyntheticSourceFile;
import ghidradwarfforge.source.SyntheticSourceFile.FunctionText;
import ghidradwarfforge.source.SyntheticSourceFile.RelativeLine;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.ProgramTypeModel.FunctionSignature;
import ghidradwarfforge.types.TypeGraph;
import ghidradwarfforge.types.TypeGraph.BaseEncoding;
import ghidradwarfforge.types.TypeGraph.BaseType;
import ghidradwarfforge.types.TypeGraph.Parameter;
import ghidradwarfforge.types.TypeGraph.TypeRef;

/** Isolated-JVM entry point for the production symbol-only exporter. */
public final class MinimalDwarfSidecarSmoke {
    private MinimalDwarfSidecarSmoke() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 6) {
            throw new IllegalArgumentException(
                "usage: MinimalDwarfSidecarSmoke <libdwarf> <libdwarfp> <input> " +
                    "<output> <function-name> <function-address>");
        }
        long address = Long.decode(args[5]);
        var source = SyntheticSourceFile.build("minimal-sidecar-smoke", "test",
            List.of(new FunctionText(args[4], address,
                "void " + args[4] + "(void)\n{\n  return;\n}\n", null,
                List.of(new RelativeLine(3, List.of(address))))));
        TypeRef signedInt = new TypeRef("smoke:int32");
        TypeGraph types = new TypeGraph(List.of(
            new BaseType(signedInt.key(), "int", 4, BaseEncoding.SIGNED)));
        FunctionSignature signature = new FunctionSignature(args[4], address, signedInt,
            List.of(new Parameter("register_parameter", signedInt, false)), List.of(),
            false, false, "smoke", "USER_DEFINED");
        VariableLocation registerParameter = new VariableLocation(args[4], address,
            "register_parameter", VariableKind.PARAMETER, 4,
            List.of(new LocationRange(address, Math.addExact(address, 0x40),
                TargetRegisterMap.forTarget("x86_64").register("RDI", 0, 32),
                new Evidence(Confidence.USER_DEFINED, "isolated exporter smoke"))));
        ProgramTypeModel typeModel = new ProgramTypeModel(types, List.of(signature),
            List.of(), new VariableStorageModel(List.of(registerParameter)));
        var result = new MinimalDwarfSidecarExporter().export(Path.of(args[2]),
            Path.of(args[3]), Path.of(args[0]), Path.of(args[1]),
            List.of(new FunctionSymbol(args[4], address, 0x40)), source, typeModel);
        System.out.printf("minimal-sidecar=PASS target=%s functions=%d sections=%s%n",
            result.target().name(), result.functionCount(), result.sectionNames());
    }
}
