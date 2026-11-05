package ghidradwarfforge.coverage;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.output.CoverageReportClaims;
import ghidradwarfforge.output.CoverageReportJson;
import ghidradwarfforge.output.CoverageTypeEvidence;
import ghidradwarfforge.output.ExportReport;
import ghidradwarfforge.output.ExportReportClaims;
import ghidradwarfforge.output.FileDigests;
import ghidradwarfforge.source.SyntheticSourceFile;
import ghidradwarfforge.source.SyntheticSourceFile.FunctionText;
import ghidradwarfforge.source.SyntheticSourceFile.RelativeLine;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.ProgramTypeModel.FunctionSignature;
import ghidradwarfforge.types.ProgramTypeModel.LocalVariable;
import ghidradwarfforge.types.TypeGraph;
import ghidradwarfforge.types.TypeGraph.*;

/** Paired real producer artifacts; the integration harness independently checks their DIEs and GDB. */
final class TypePairEmissionSmoke {
    private TypePairEmissionSmoke() { }

    static void run(Path input, Path directory, Path consumer, Path producer, Map<String, Long> symbols)
            throws Exception {
        byte[] original = Files.readAllBytes(input);
        for (String phase : List.of("before", "after", "unattached")) {
            Path output = directory.resolve("type-" + phase + ".dbg");
            produce(input, output, consumer, producer, symbols, phase);
            var paths = List.of(output, Path.of(output + ".c"), Path.of(output + ".report.json"));
            var first = new java.util.ArrayList<byte[]>();
            for (Path path : paths) first.add(Files.readAllBytes(path));
            produce(input, output, consumer, producer, symbols, phase);
            for (int i = 0; i < paths.size(); i++) {
                if (!Arrays.equals(first.get(i), Files.readAllBytes(paths.get(i)))) {
                    throw new AssertionError("nondeterministic type pair " + paths.get(i));
                }
            }
        }
        compare(directory, "before", "after");
        compare(directory, "after", "before");
        compare(directory, "after", "unattached");
        compare(directory, "after", "after");
        if (!Arrays.equals(original, Files.readAllBytes(input))) throw new AssertionError("changed type-pair input");
        System.out.println("type-pair-emission=PASS");
    }

    private static void compare(Path directory, String before, String after) throws Exception {
        Path log = directory.resolve("type-compare-" + before + "-" + after + ".log");
        var process = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
            "-cp", System.getProperty("java.class.path"), "ghidradwarfforge.output.CoverageReportTool",
            "--before", directory.resolve("type-" + before + ".dbg.report.json").toString(),
            "--report", directory.resolve("type-" + after + ".dbg.report.json").toString())
            .redirectErrorStream(true).redirectOutput(log.toFile()).start();
        try {
            if (!process.waitFor(30, java.util.concurrent.TimeUnit.SECONDS) || process.exitValue() != 0) {
                throw new AssertionError("type-pair CLI failed: " + log);
            }
        }
        finally {
            if (process.isAlive()) process.destroyForcibly();
        }
    }

    private static void produce(Path input, Path output, Path consumer, Path producer,
            Map<String, Long> symbols, String phase) throws Exception {
        long entry = symbols.get("observed"), end = symbols.get("observed_end");
        var scalar = new TypeRef("u64");
        boolean swapped = !phase.equals("before");
        var graph = new TypeGraph(List.of(new BaseType("u64", "uint64_t", 8, BaseEncoding.UNSIGNED),
            payload("a", "PayloadA", !swapped, scalar), payload("b", "PayloadB", swapped, scalar)));
        var signature = new FunctionSignature("observed", entry, scalar,
            List.of(new Parameter("x", scalar, false)),
            List.of(new LocalVariable("payload_a", 8, new TypeRef("a"), 0, false, "USER_DEFINED"),
                new LocalVariable("payload_b", 8, new TypeRef("b"), 0, false, "USER_DEFINED")),
            false, false, "default", "USER_DEFINED");
        var model = new ProgramTypeModel(graph, List.of(signature), List.of());
        var function = new FunctionSymbol("observed", entry, end - entry);
        var text = phase.equals("unattached")
            ? new FunctionText("observed", entry, null, "controlled type-pair source failure")
            : new FunctionText("observed", entry,
                "uint64_t observed(uint64_t x)\n{\n    x = x;\n    return x;\n}\n", null,
                List.of(new RelativeLine(2, List.of(entry)),
                    new RelativeLine(3, List.of(symbols.get("observed_moved"))),
                    new RelativeLine(4, List.of(symbols.get("observed_return")))));
        var source = SyntheticSourceFile.build("type-pair fixture", "controlled recovered type definitions", List.of(text));
        var result = new MinimalDwarfSidecarExporter().export(input, output, consumer, producer,
            List.of(function), source, model);
        Path sourcePath = Path.of(output + ".c");
        Files.write(sourcePath, source.utf8());
        var decoded = List.of(new DecodedInstructions(function,
            List.of(entry, symbols.get("observed_moved"), symbols.get("observed_return")), ""));
        var coverage = ExportCoverage.build(model, source, decoded, result.emission(), () -> false);
        var claims = new CoverageReportClaims(new CoverageReportJson.Profile("x86:LE:64:default", "gcc"), coverage,
            CoverageTypeEvidence.capture(model, result.emission(), coverage, () -> false));
        var report = ExportReport.completed(result.target(), result.libdwarfVersion(),
            input, FileDigests.read(input).sha256(), output, FileDigests.read(output).sha256(),
            sourcePath, FileDigests.read(sourcePath).sha256(), result.functionCount(), result.sectionNames(),
            source, model, List.of(), List.of());
        Path reportPath = Path.of(output + ".report.json");
        Files.writeString(reportPath, report.toJsonWithCoverage(claims, () -> false));
        if (!ExportReportClaims.readWithCoverage(reportPath, () -> false).coverage().equals(claims)) {
            throw new AssertionError("native type-pair report roundtrip");
        }
    }

    private static TypeNode payload(String key, String name, boolean resolved, TypeRef scalar) {
        return resolved
            ? new AggregateType(key, name, 8, AggregateKind.STRUCTURE, List.of(new Member("value", scalar, 0)))
            : new OpaqueType(key, name, 8, "fixture has no recovered member definition");
    }
}
