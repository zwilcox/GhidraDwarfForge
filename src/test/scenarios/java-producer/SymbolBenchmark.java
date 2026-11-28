package evaluation;

import static evaluation.JavaUnitWriter.Field.*;
import evaluation.JavaUnitWriter.Die;
import evaluation.JavaUnitWriter.Id;
import evaluation.JavaUnitWriter.Tag;
import ghidradwarfforge.dwarf.DwarfAddressRanges;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.elf.MatchedElfSidecarWriter;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Measures a symbol-only export of linked functions. Inventory extraction is outside the timer. */
final class SymbolBenchmark {
    private static void javaExport(Path input, Path output, List<FunctionSymbol> functions) throws Exception {
        var elf = ElfImage.readForExport(input);
        int width = elf.is64Bit() ? 8 : 4;
        var children = new ArrayList<Die>();
        for (var function : functions) {
            children.add(new Die(new Id(function.name()), Tag.FUNCTION,
                Map.of(NAME, function.name(), LOW_PC, function.address(), HIGH_PC, function.size()), List.of()));
        }
        var unit = new Die(new Id("#unit"), Tag.UNIT, Map.of(NAME, output.getFileName() + ".c",
            COMP_DIR, output.getParent().toString(), LANGUAGE, 0x1d, PRODUCER, "Forge Java evaluation"), children);
        var sections = JavaUnitWriter.write(unit, width, elf.byteOrder(),
            Map.of(".debug_aranges", DwarfAddressRanges.build(functions, width, elf.byteOrder())), () -> false);
        new MatchedElfSidecarWriter().write(elf, output, sections, List.of(), () -> false);
    }

    public static void main(String[] args) throws Exception {
        Path input = Path.of(args[1]);
        Path output = Path.of(args[2]);
        Path libraries = Path.of(args[3]);
        var functions = new ArrayList<FunctionSymbol>();
        for (String row : Files.readAllLines(Path.of(args[4]))) {
            String[] fields = row.split("\\t");
            functions.add(new FunctionSymbol(fields[2], EvaluationFixture.hex(fields[0]), EvaluationFixture.hex(fields[1])));
        }
        for (int i = 0; i < Integer.parseInt(args[5]); i++) {
            long start = System.nanoTime();
            switch (args[0]) {
                case "java" -> javaExport(input, output, functions);
                case "libdwarf" -> new MinimalDwarfSidecarExporter().export(input, output,
                    libraries.resolve("libdwarf.so.2"), libraries.resolve("libdwarfp.so.2.3.2"), functions);
                default -> throw new IllegalArgumentException("unknown producer " + args[0]);
            }
            System.out.println("export-ns=" + (System.nanoTime() - start));
        }
    }
}
