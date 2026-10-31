package ghidradwarfforge.elf;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

import com.google.gson.JsonParser;
import ghidradwarfforge.locations.VariableStorageModel;
import ghidradwarfforge.source.SyntheticSourceFile;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.types.ClassScopeModel;
import ghidradwarfforge.types.ClassScopeModel.FunctionReference;
import ghidradwarfforge.types.FunctionRelations;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.TypeGraph;

/** Isolated native producer using exact compiler-observed entries and original body hashes. */
public final class FunctionRelationshipProducer {
    public static void main(String[] args) throws Exception {
        if (args.length != 6) throw new IllegalArgumentException("consumer producer input output symbols.json variant");
        Path input = Path.of(args[2]), output = Path.of(args[3]);
        var symbols = JsonParser.parseString(Files.readString(Path.of(args[4]))).getAsJsonObject();
        var gateway = symbols.getAsJsonObject("gateway");
        var implementation = symbols.getAsJsonObject("implementation");
        long start = gateway.get("entry").getAsLong(), size = gateway.get("size").getAsLong();
        long target = implementation.get("entry").getAsLong(), targetSize = implementation.get("size").getAsLong();
        var functions = List.of(new FunctionSymbol("analyst_gateway", start, size),
            new FunctionSymbol("implementation", target, targetSize));
        var integer = new TypeGraph.TypeRef("int");
        var typeGraph = new TypeGraph(List.of(new TypeGraph.BaseType("int", "int", 4, TypeGraph.BaseEncoding.SIGNED)));
        var parameters = List.of(new TypeGraph.Parameter("value", integer, false));
        var signatures = functions.stream().map(f -> new ProgramTypeModel.FunctionSignature(f.name(), f.address(),
            integer, parameters, List.of(), false, false, "default", "USER_DEFINED")).toList();
        if (!List.of("plain", "related", "external", "failed", "bad-hash", "bad-owner", "collision").contains(args[5])) throw new IllegalArgumentException("unknown variant");
        var declarations = args[5].equals("external") ? List.of(new ProgramTypeModel.FunctionDeclaration(
            "external:3", "external_target", integer, parameters, false, false, "default", "USER_DEFINED")) :
            List.<ProgramTypeModel.FunctionDeclaration>of();
        // The external variant exercises addressless references only. Its metadata is
        // a model control, not an assertion about this executable's actual tail target.
        var destination = args[5].equals("external") ? FunctionReference.declaration("external_target", "external:3") :
            FunctionReference.definition("implementation", target);
        var relations = args[5].equals("plain") ? FunctionRelations.empty() : new FunctionRelations(List.of(
            new FunctionRelations.Thunk(1, FunctionReference.definition("analyst_gateway", start), 2,
                destination, "isolated serialization control")));
        var model = new ProgramTypeModel(typeGraph, signatures, List.of(), new VariableStorageModel(List.of()), List.of(),
            declarations, List.of(), ClassScopeModel.empty(), relations);
        var elf = ElfImage.read(input);
        var section = elf.sections().stream().filter(s -> s.type == 1 && s.address <= target &&
            target - s.address <= s.size && targetSize <= s.size - (target - s.address)).findFirst().orElseThrow();
        byte[] bytes = elf.sectionData(section);
        String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Arrays.copyOfRange(bytes,
            Math.toIntExact(target - section.address), Math.toIntExact(target - section.address + targetSize))));
        var aliases = List.of(new ElfFunctionAlias(args[5].equals("collision") ? "gateway" : "analyst_alias",
            args[5].equals("bad-owner") ? "unowned" : "implementation", target, targetSize,
            args[5].equals("bad-hash") ? "0".repeat(64) : hash));
        var source = args[5].equals("failed") ? SyntheticSourceFile.build("fixture", "fixture", List.of(
            new SyntheticSourceFile.FunctionText("analyst_gateway", start, null, "controlled producer fixture failure"))) : null;
        new MinimalDwarfSidecarExporter().export(input, output, Path.of(args[0]), Path.of(args[1]),
            functions, source, model, output.getFileName() + ".c", () -> false, List.of(), aliases, System.out::println);
        System.out.println("function-relationship-producer=" + args[5] + " PASS java=" + System.getProperty("java.version"));
    }
}
