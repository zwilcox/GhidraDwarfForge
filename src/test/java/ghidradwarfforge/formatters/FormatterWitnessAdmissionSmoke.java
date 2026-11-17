package ghidradwarfforge.formatters;

import ghidradwarfforge.elf.Arm32SectionModesSmoke;
import ghidradwarfforge.elf.DebugSectionCompression;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.TypeGraph;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Native-free admission: unavailable library placeholders must never reach JNA loading. */
final class FormatterWitnessAdmissionSmoke {
    private static final String WITNESS = "__forge_formatter_" + "a".repeat(64);
    private static int checks;

    static void run(Path parent) throws Exception {
        Path root = Files.createDirectory(parent.resolve("witness-admission"));
        byte[] original = Arm32SectionModesSmoke.fixture();
        Path input = Files.write(root.resolve("input.elf"), original);
        byte[] notLibrary = "native loading is forbidden in these admission tests".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        Path library = Files.write(root.resolve("unavailable-native-library"), notLibrary);
        Path output = root.resolve("output.dbg");
        byte[] sentinel = "previous sidecar generation".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        var inputIdentity = Files.readAttributes(input, BasicFileAttributes.class);
        var value = new TypeGraph.TypeRef("value");
        var integer = new TypeGraph.BaseType(value.key(), "int", 4, TypeGraph.BaseEncoding.SIGNED);
        var ordinary = new ProgramTypeModel(new TypeGraph(List.of(integer)), List.of(), List.of());
        var safe = List.of(new FunctionSymbol("safe", Arm32SectionModesSmoke.START, 4));

        for (String malformed : List.of("__forge_formatter_" + "a".repeat(63),
                "__forge_formatter_" + "A".repeat(64), "forge_formatter_" + "a".repeat(64))) {
            constructorRefuses(Map.of(value.key(), malformed));
        }
        constructorRefuses(Map.of("first", WITNESS, "second", WITNESS));
        new MinimalDwarfSidecarExporter(DebugSectionCompression.NONE, Map.of(value.key(), WITNESS));
        checks++;

        for (String scenario : List.of("missing-model", "missing-key", "function-name", "type-name", "global-name")) {
            ProgramTypeModel model = ordinary;
            var functions = safe;
            String key = value.key();
            switch (scenario) {
                case "missing-model" -> model = null;
                case "missing-key" -> key = "absent";
                case "function-name" -> functions = List.of(new FunctionSymbol(WITNESS, Arm32SectionModesSmoke.START, 4));
                case "type-name" -> model = new ProgramTypeModel(new TypeGraph(List.of(integer,
                    new TypeGraph.BaseType("collision", WITNESS, 4, TypeGraph.BaseEncoding.UNSIGNED))), List.of(), List.of());
                case "global-name" -> model = new ProgramTypeModel(new TypeGraph(List.of(integer)), List.of(),
                    List.of(new ProgramTypeModel.GlobalVariable(WITNESS, Arm32SectionModesSmoke.START, 4,
                        value, false, "EXPLICIT_TEST_MODEL")));
                default -> throw new AssertionError(scenario);
            }
            for (boolean existing : new boolean[] {false, true}) {
                Files.deleteIfExists(output);
                BasicFileAttributes before = null;
                if (existing) {
                    Files.write(output, sentinel);
                    before = Files.readAttributes(output, BasicFileAttributes.class);
                }
                var exporter = new MinimalDwarfSidecarExporter(DebugSectionCompression.NONE, Map.of(key, WITNESS));
                try {
                    exporter.export(input, output, library, library, functions, null, model);
                    throw new AssertionError("formatter witness conflict accepted: " + scenario);
                }
                catch (IllegalArgumentException expected) {
                    require(expected.getMessage().contains("missing or conflicting formatter canonical type witness"),
                        "wrong admission rejection: " + scenario + " " + expected);
                }
                require(Files.exists(output) == existing, "refusal changed output existence");
                if (existing) {
                    var after = Files.readAttributes(output, BasicFileAttributes.class);
                    require(Arrays.equals(sentinel, Files.readAllBytes(output)) &&
                        Objects.equals(before.fileKey(), after.fileKey()) &&
                        before.lastModifiedTime().equals(after.lastModifiedTime()), "existing sidecar replaced");
                }
                require(Arrays.equals(original, Files.readAllBytes(input)) &&
                    Files.readAttributes(input, BasicFileAttributes.class).lastModifiedTime().equals(inputIdentity.lastModifiedTime()),
                    "original ELF changed");
                require(Arrays.equals(notLibrary, Files.readAllBytes(library)), "library placeholder changed");
                try (var paths = Files.list(root)) {
                    require(paths.count() == (existing ? 3 : 2), "refusal left a source or staging artifact");
                }
            }
        }
        System.out.println("formatter-witness-admission=PASS checks=" + checks);
    }

    private static void constructorRefuses(Map<String, String> aliases) {
        try {
            new MinimalDwarfSidecarExporter(DebugSectionCompression.NONE, aliases);
            throw new AssertionError("invalid formatter witness names accepted");
        }
        catch (IllegalArgumentException expected) {
            require(expected.getMessage().contains("invalid formatter type witness names"), "wrong constructor rejection");
        }
    }

    private static void require(boolean value, String reason) {
        checks++;
        if (!value) throw new AssertionError(reason);
    }
}
