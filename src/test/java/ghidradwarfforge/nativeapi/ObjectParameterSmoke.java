package ghidradwarfforge.nativeapi;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.source.SyntheticSourceFile;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.TypeGraph;
import ghidradwarfforge.types.TypeGraph.*;

/** Object identity is explicit metadata, independent of parameter spelling/storage. */
public final class ObjectParameterSmoke {
    private static final TypeRef INTEGER = new TypeRef("int");
    private static final TypeRef POINTER = new TypeRef("pointer");

    private static ProgramTypeModel.FunctionSignature signature(String name, long address,
            List<Parameter> parameters) {
        return new ProgramTypeModel.FunctionSignature(name, address, INTEGER, parameters,
            List.of(), false, false, "default", "USER_DEFINED");
    }

    private static void reject(Runnable action) {
        try {
            action.run();
        }
        catch (IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError("invalid object parameter accepted");
    }

    public static void main(String[] args) throws Exception {
        var graph = new TypeGraph(List.of(
            new BaseType("int", "int", 4, BaseEncoding.SIGNED),
            new AggregateType("object", "Counter", 4, AggregateKind.STRUCTURE,
                List.of(new Member("value", INTEGER, 0))),
            new IndirectionType("pointer", "Counter *", 8, IndirectionKind.POINTER, new TypeRef("object")),
            new QualifiedType("qualified", "Counter * const", 8, List.of(Qualifier.CONST), POINTER),
            new TypedefType("alias", "handle", 8, new TypeRef("qualified")),
            new TypedefType("cycle", "cycle", 8, new TypeRef("cycle"))));
        var object = new Parameter("receiver", new TypeRef("alias"), true, false, true);
        var ordinary = new Parameter("this", POINTER, false);
        if (ordinary.objectPointer() || new Parameter("this", POINTER, true, false).objectPointer() ||
                new Parameter("this", POINTER, true, true).objectPointer()) {
            throw new AssertionError("object identity inferred from name or artificial flag");
        }
        reject(() -> new Parameter("this", POINTER, false, false, true));
        reject(() -> new Parameter("this", POINTER, true, true, true));
        reject(() -> signature("bad", 0, List.of(object, object)));
        reject(() -> new ProgramTypeModel.FunctionDeclaration("bad", "bad", INTEGER,
            List.of(object, object), false, false, "default", "USER_DEFINED"));
        for (TypeRef invalid : List.of(INTEGER, new TypeRef("cycle"), new TypeRef("missing"))) {
            var parameter = new Parameter("receiver", invalid, true, false, true);
            reject(() -> new ProgramTypeModel(graph, List.of(signature("bad", 0, List.of(parameter))), List.of()));
            reject(() -> new ProgramTypeModel(graph, List.of(), List.of(),
                new ghidradwarfforge.locations.VariableStorageModel(List.of()), List.of(),
                List.of(new ProgramTypeModel.FunctionDeclaration("bad", "bad", INTEGER,
                    List.of(parameter), false, false, "default", "USER_DEFINED"))));
        }
        new ProgramTypeModel(graph, List.of(signature("method", 0, List.of(object))), List.of());
        System.out.println("object-parameter-model=PASS");
        if (args.length == 0) {
            return;
        }
        if (args.length != 6) {
            throw new IllegalArgumentException("consumer producer input output entry size");
        }
        long entry = Long.decode(args[4]);
        long size = Long.decode(args[5]);
        if (size < 2) {
            throw new IllegalArgumentException("fixture too short");
        }
        var functions = List.of(new FunctionSymbol("Counter::method", entry, size / 2),
            new FunctionSymbol("ordinary", entry + size / 2, size - size / 2));
        // The cyclic alias above is a deliberately invalid model control, not
        // a type to serialize into the validator fixture.
        var exportTypes = new TypeGraph(graph.nodes().stream()
            .filter(node -> !node.key().equals("cycle")).toList());
        var model = new ProgramTypeModel(exportTypes, List.of(
            signature("Counter::method", entry, List.of(object)),
            signature("ordinary", entry + size / 2, List.of(ordinary))), List.of(),
            new ghidradwarfforge.locations.VariableStorageModel(List.of()), List.of(), List.of(
                new ProgramTypeModel.FunctionDeclaration("external", "Counter::external", INTEGER,
                    List.of(object), false, false, "default", "USER_DEFINED")));
        Path input = Path.of(args[2]);
        byte[] original = Files.readAllBytes(input);
        var exporter = new MinimalDwarfSidecarExporter();
        byte[] previous = null;
        for (int iteration = 0; iteration < 2; iteration++) {
            exporter.export(input, Path.of(args[3]), Path.of(args[0]), Path.of(args[1]),
                functions, null, model);
            byte[] current = Files.readAllBytes(Path.of(args[3]));
            if (previous != null && !java.util.Arrays.equals(previous, current)) {
                throw new AssertionError("nondeterministic object reference");
            }
            previous = current;
        }
        var failure = SyntheticSourceFile.build("fixture", "fixture", List.of(
            new SyntheticSourceFile.FunctionText("Counter::method", entry, null, "controlled failure")));
        exporter.export(input, Path.of(args[3] + ".failed"), Path.of(args[0]), Path.of(args[1]),
            functions, failure, model);
        if (!java.util.Arrays.equals(original, Files.readAllBytes(input))) {
            throw new AssertionError("input changed");
        }
        System.out.println("object-parameter-native=PASS");
    }
}
