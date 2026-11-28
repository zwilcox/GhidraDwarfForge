package evaluation;

import static evaluation.JavaUnitWriter.Field.*;
import static ghidradwarfforge.locations.VariableStorageModel.*;
import static ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import static ghidradwarfforge.types.TypeGraph.*;
import evaluation.JavaUnitWriter.Die;
import evaluation.JavaUnitWriter.Field;
import evaluation.JavaUnitWriter.Id;
import evaluation.JavaUnitWriter.Tag;
import ghidradwarfforge.dwarf.Dwarf5LineTable;
import ghidradwarfforge.dwarf.Dwarf5LocationLists;
import ghidradwarfforge.dwarf.Dwarf5RangeLists;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.elf.MatchedElfSidecarWriter;
import ghidradwarfforge.locations.VariableStorageModel;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter;
import ghidradwarfforge.output.ArtifactPairPublisher;
import ghidradwarfforge.output.OutputPathPolicy;
import ghidradwarfforge.source.SyntheticSourceFile;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.TypeGraph;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/** Explicit compiler-fixture model for an A/B comparison of DIE production. */
record EvaluationFixture(String function, long start, long size, long split, long first, long second,
        boolean rich) {
    private static final String EVIDENCE = "explicit linked fixture symbols";
    private static final Id INTEGER_ID = new Id("int");
    private static final Id POINTER_ID = new Id("pointer");
    private static final Id NODE_ID = new Id("node");

    EvaluationFixture {
        var range = new MinimalDwarfSidecarExporter.FunctionRange(start, size);
        if (function == null || function.isBlank() || !range.contains(split) || split == start) {
            throw new IllegalArgumentException("invalid function or split outside fixture");
        }
    }

    FunctionSymbol symbol() { return new FunctionSymbol(function, start, size); }

    SyntheticSourceFile source() {
        String code = "int " + function + "(void)\n{\n    /* observed in first storage */\n    return moving.value;\n}\n";
        return SyntheticSourceFile.build("java-producer-evaluation", "test", List.of(
            new SyntheticSourceFile.FunctionText(function, start, code, null, List.of(
                new SyntheticSourceFile.RelativeLine(1, List.of(start)),
                new SyntheticSourceFile.RelativeLine(4, List.of(split))))));
    }

    VariableLocation moving(int width) {
        var evidence = new Evidence(Confidence.USER_DEFINED, EVIDENCE);
        return new VariableLocation(function, start, "moving", VariableKind.LOCAL, width * 2,
            List.of(new LocationRange(start, split, new MemoryStorage(first), evidence),
                new LocationRange(split, start + size, new MemoryStorage(second), evidence)));
    }

    ProgramTypeModel nativeModel(int width) {
        var integer = new TypeRef(INTEGER_ID.key());
        var node = new TypeRef(NODE_ID.key());
        var pointer = new TypeRef(POINTER_ID.key());
        var base = new BaseType(integer.key(), "int", 4, BaseEncoding.SIGNED);
        var graph = rich ? new TypeGraph(List.of(base,
            new AggregateType(node.key(), "EvalNode", width * 2, AggregateKind.STRUCTURE, List.of(
                new Member("next", pointer, 0), new Member("value", integer, width))),
            new IndirectionType(pointer.key(), "EvalNode *", width, IndirectionKind.POINTER, node))) :
            new TypeGraph(List.of(base));
        var locals = rich ? List.of(new ProgramTypeModel.LocalVariable("moving", width * 2, node, 0, true, EVIDENCE))
            : List.<ProgramTypeModel.LocalVariable>of();
        var signature = new ProgramTypeModel.FunctionSignature(function, start, integer, List.of(), locals,
            false, false, "default", EVIDENCE);
        return new ProgramTypeModel(graph, List.of(signature), List.of(),
            new VariableStorageModel(rich ? List.of(moving(width)) : List.of()));
    }

    private static Die leaf(String id, Tag tag, Map<Field, Object> attributes) {
        return new Die(new Id(id), tag, attributes, List.of());
    }

    Map<String, byte[]> javaSections(ElfImage elf, Path sourcePath, SyntheticSourceFile source,
            BooleanSupplier cancelled) {
        int width = elf.is64Bit() ? 8 : 4;
        var order = elf.byteOrder();
        String basename = sourcePath.getFileName().toString();
        String directory = sourcePath.getParent().toString();
        var functions = List.of(symbol());
        var extra = new LinkedHashMap<String, byte[]>();
        extra.put(".debug_line", Dwarf5LineTable.build(basename, directory, width, order, functions, source.mappedLines()));
        var ranges = Dwarf5RangeLists.build(functions, width, order);
        if (!ranges.empty()) throw new IllegalArgumentException("evaluation fixture requires a contiguous function");
        var children = new java.util.ArrayList<Die>();
        var local = moving(width);
        var locations = Dwarf5LocationLists.build(rich ? List.of(local) : List.of(), width, order, cancelled);
        List<Die> variables = List.of();
        if (rich) {
            if (!locations.offsets().containsKey(local)) throw new IllegalArgumentException("missing location plan");
            extra.put(".debug_loclists", locations.section());
            variables = List.of(leaf("local", Tag.LOCAL, Map.of(NAME, "moving", TYPE, NODE_ID,
                LOCATION, locations.offsets().get(local))));
        }
        children.add(new Die(new Id("function"), Tag.FUNCTION,
            Map.of(NAME, function, LOW_PC, start, HIGH_PC, size, TYPE, INTEGER_ID, EXTERNAL, true,
                FILE, 0, LINE, source.functions().getFirst().startLine()), variables));
        if (rich) {
            children.add(new Die(NODE_ID, Tag.STRUCT, Map.of(NAME, "EvalNode", SIZE, width * 2), List.of(
                leaf("member.next", Tag.MEMBER, Map.of(NAME, "next", TYPE, POINTER_ID, MEMBER_OFFSET, 0)),
                leaf("member.value", Tag.MEMBER, Map.of(NAME, "value", TYPE, INTEGER_ID, MEMBER_OFFSET, width)))));
            children.add(new Die(POINTER_ID, Tag.POINTER, Map.of(SIZE, width, TYPE, NODE_ID), List.of()));
        }
        children.add(new Die(INTEGER_ID, Tag.BASE, Map.of(NAME, "int", SIZE, 4, ENCODING, 5), List.of()));
        var unit = new Die(new Id("unit"), Tag.UNIT,
            Map.of(NAME, basename, COMP_DIR, directory, PRODUCER, "Forge Java evaluation", LANGUAGE, 0x1d,
                LOW_PC, start, HIGH_PC, size, STMT_LIST, 0), children);
        return JavaUnitWriter.write(unit, width, order, extra, cancelled);
    }

    void export(String backend, Path input, Path output, Path nativeDirectory, BooleanSupplier cancelled)
            throws Exception {
        var paths = OutputPathPolicy.resolve(input, output);
        var elf = ElfImage.readForExport(paths.input());
        var source = source();
        ArtifactPairPublisher.stageAndPublish(paths.artifact(), paths.source(), stage -> {
            switch (backend) {
                case "java" -> new MatchedElfSidecarWriter().write(elf, stage,
                    javaSections(elf, paths.source(), source, cancelled), List.of(), cancelled);
                case "libdwarf" -> new MinimalDwarfSidecarExporter().export(paths.input(), stage,
                    nativeDirectory.resolve("libdwarf.so.2"), nativeDirectory.resolve("libdwarfp.so.2.3.2"),
                    List.of(symbol()), source, nativeModel(elf.is64Bit() ? 8 : 4),
                    paths.source().getFileName().toString(), cancelled);
                default -> throw new IllegalArgumentException("unsupported backend " + backend);
            }
        }, stage -> Files.write(stage, source.utf8()), () -> {
            if (cancelled.getAsBoolean()) throw new CancellationException("cancelled before pair publication");
        });
    }

    static long hex(String value) { return Long.parseUnsignedLong(value, 16); }

    public static void main(String[] args) throws Exception {
        if (args.length != 11) throw new IllegalArgumentException(
            "backend native-dir input output simple|rich name start size split first second (numbers hexadecimal)");
        boolean rich = switch (args[4]) {
            case "simple" -> false;
            case "rich" -> true;
            default -> throw new IllegalArgumentException("unknown fixture model " + args[4]);
        };
        var model = new EvaluationFixture(args[5], hex(args[6]), hex(args[7]), hex(args[8]), hex(args[9]), hex(args[10]), rich);
        model.export(args[0], Path.of(args[2]), Path.of(args[3]), Path.of(args[1]), () -> false);
    }
}
