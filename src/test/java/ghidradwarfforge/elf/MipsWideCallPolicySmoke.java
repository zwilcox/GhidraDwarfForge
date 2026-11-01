package ghidradwarfforge.elf;

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.GhidraCompilerCallPolicy;
import ghidradwarfforge.locations.VariableStorageModel;
import ghidradwarfforge.nativeapi.DwarfTarget;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.ProgramTypeModel.FunctionDeclaration;
import ghidradwarfforge.types.ProgramTypeModel.FunctionSignature;
import ghidradwarfforge.types.TypeGraph;
import ghidradwarfforge.types.TypeGraph.*;

/** Metadata disagreement and typed call transfers through definitions, declarations and callbacks. */
public final class MipsWideCallPolicySmoke {
    private static int checks;
    private record Case(String result, String argument, boolean variadic, String existing, boolean allowed) { }
    private static final List<Case> CASES = List.of(
        new Case("i", "word", false, "", true),
        new Case("word", "i", false, "", true),
        new Case("f", "d", false, "", true),
        new Case("d", "f", false, "", true),
        new Case("pair", "large", false, "", true),
        new Case("large", "pair", false, "", true),
        new Case("qualified", "p", false, "prior storage restriction", true),
        new Case("v", "enum", false, "", true),
        new Case("p", "i", false, "", true),
        new Case("i", "cycle1", false, "", false),
        new Case("i", "aliasBadSize", false, "", false),
        new Case("i", "v", false, "", false),
        new Case("i", "opaque", false, "", false),
        new Case("opaque", "i", false, "", false),
        new Case("i", "wrongPointer", false, "", false),
        new Case("i", "reference", false, "", false),
        new Case("i", "i", true, "", false),
        new Case("quad", "i", false, "", false),
        new Case("i", "quad", false, "", false),
        new Case("i", "union", false, "", false),
        new Case("i", "padded", false, "", false),
        new Case("i", "overlap", false, "", false),
        new Case("i", "fpPair", false, "", false),
        new Case("i", "bits", false, "", false),
        new Case("i", "nested", false, "", false),
        new Case("i", "array", false, "", false),
        new Case("i", "huge", false, "", false));

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        Path root = Files.createTempDirectory("forge-wide-calls-");
        for (boolean elf64 : List.of(false, true)) {
            for (var order : List.of(ByteOrder.BIG_ENDIAN, ByteOrder.LITTLE_ENDIAN)) {
                var model = model(elf64 ? 8 : 4);
                for (int carrier : List.of(0, 1, 2, 3)) {
                    var fixture = fixture(root.resolve("case-" + elf64 + "-" + order + "-" + carrier), elf64, order, carrier);
                    var image = ElfImage.read(fixture.path());
                    var output = DwarfTarget.fromElf(image).applyCallRestrictions(image, model, () -> false, ignored -> { });
                    verify(model, output, carrier != 0);
                    require(output.equals(MipsWideCallPolicy.apply(image, output, () -> false, ignored -> { })), "not idempotent");
                    AtomicInteger count = new AtomicInteger();
                    MipsWideCallPolicy.apply(image, model, () -> { count.incrementAndGet(); return false; }, ignored -> { });
                    for (int stop : List.of(1, count.get() / 2, count.get())) {
                        AtomicInteger current = new AtomicInteger();
                        try {
                            MipsWideCallPolicy.apply(image, model, () -> current.incrementAndGet() >= stop, ignored -> { });
                            throw new AssertionError("ignored cancellation");
                        }
                        catch (CancellationException expected) { checks++; }
                    }
                    if (carrier == 3) {
                        programCases(image, model);
                        hiddenStorageCases(image, model);
                        metadataMutations(fixture, model);
                    }
                }
            }
        }
        System.out.println("mips-wide-call-policy-smoke=PASS checks=" + checks);
    }

    private static void hiddenStorageCases(ElfImage image, ProgramTypeModel model) throws Exception {
        var nodes = new ArrayList<TypeNode>(model.types().nodes());
        nodes.add(new IndirectionType("hidden", "Large *", image.is64Bit() ? 8 : 4,
            IndirectionKind.POINTER, new TypeRef("large")));
        var correct = new Parameter("hidden", new TypeRef("hidden"), true, true);
        var wrongType = new Parameter("hidden", new TypeRef("p"), true, true);
        var wrongWidth = new Parameter("hidden", new TypeRef("wrongPointer"), true, true);
        var objectPointer = new Parameter("this", new TypeRef("p"), true, false, true);
        for (var hidden : List.of(List.<Parameter>of(), List.of(correct), List.of(correct, correct),
                List.of(wrongType), List.of(wrongWidth), List.of(objectPointer))) {
            var parameters = new ArrayList<Parameter>(hidden);
            parameters.add(new Parameter("arg", new TypeRef("large"), false));
            var function = new FunctionSignature("hidden", 0x1000, new TypeRef("large"), parameters,
                List.of(), false, false, "default", "USER_DEFINED", false, "");
            var input = new ProgramTypeModel(new TypeGraph(nodes), List.of(function), List.of());
            var output = MipsWideCallPolicy.apply(image, input, () -> false, ignored -> { });
            require(output.functions().getFirst().debuggerCallsDisabled() ==
                !(hidden.isEmpty() || hidden.equals(List.of(correct))), "hidden result contract bypass");
        }
    }

    private static void metadataMutations(ElfBuildIdFixtures.Fixture fixture, ProgramTypeModel model) throws Exception {
        byte[] original = Files.readAllBytes(fixture.path());
        long flags = fixture.elf64() ? 48 : 36;
        // Each independent disagreement must disable every signature, including scalar integer calls.
        for (long[] mutation : List.of(new long[] { 7, 1, 9 }, new long[] { 8, 1, 2 },
                new long[] { 16, 2, 1 }, new long[] { flags, 4, 0x80001000L },
                new long[] { flags, 4, fixture.elf64() ? 0x80000020L : 0x80000000L },
                new long[] { flags, 4, 0x90000020L }, new long[] { flags, 4, 0x80000420L },
                new long[] { fixture.dataOffset(), 2, 1 }, new long[] { fixture.dataOffset() + 2, 1, 32 },
                new long[] { fixture.dataOffset() + 3, 1, 6 }, new long[] { fixture.dataOffset() + 4, 1, 1 },
                new long[] { fixture.dataOffset() + 5, 1, 1 }, new long[] { fixture.dataOffset() + 6, 1, 1 },
                new long[] { fixture.dataOffset() + 7, 1, 5 }, new long[] { fixture.dataOffset() + 8, 4, 1 },
                new long[] { fixture.dataOffset() + 12, 4, 1 }, new long[] { fixture.dataOffset() + 16, 4, 2 },
                new long[] { fixture.dataOffset() + 20, 4, 1 })) {
            fixture.patch(mutation[0], (int) mutation[1], mutation[2]);
            var image = ElfImage.read(fixture.path());
            require(!MipsWideCallPolicy.metadataRestriction(image, () -> false).isEmpty(), "metadata disagreement allowed");
            if (MipsWideCallPolicy.isWideCandidate(image)) {
                verify(model, MipsWideCallPolicy.apply(image, model, () -> false, ignored -> { }), false);
            }
            Files.write(fixture.path(), original);
        }
        for (int os : List.of(0, 3)) {
            for (int version : List.of(0, 1)) {
                for (int type : List.of(2, 3)) {
                    fixture.patch(7, 1, os);
                    fixture.patch(8, 1, version);
                    fixture.patch(16, 2, type);
                    require(MipsWideCallPolicy.metadataRestriction(ElfImage.read(fixture.path()), () -> false).isEmpty(),
                        "supported metadata rejected");
                }
            }
        }
        Files.write(fixture.path(), original);
    }

    private static void programCases(ElfImage image, ProgramTypeModel model) throws Exception {
        boolean big = image.byteOrder() == ByteOrder.BIG_ENDIAN;
        String correct = "MIPS:" + (big ? "BE" : "LE") + ":64:" + (image.is64Bit() ? "default" : "64-32addr");
        String compiler = image.is64Bit() ? "default" : "n32";
        for (String languageId : List.of("MIPS:BE:64:default", "MIPS:LE:64:default",
                "MIPS:BE:64:64-32addr", "MIPS:LE:64:64-32addr", "MIPS:BE:32:default", "MIPS:LE:32:default")) {
            var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(languageId));
            for (var spec : language.getCompatibleCompilerSpecDescriptions()) {
                var owner = new Object();
                var program = new ProgramDB("wide-call-policy", language,
                    language.getCompilerSpecByID(new CompilerSpecID(spec.getCompilerSpecID().toString())), owner);
                try {
                    boolean match = languageId.equals(correct) && spec.getCompilerSpecID().toString().equals(compiler);
                    var output = GhidraCompilerCallPolicy.apply(program, DwarfTarget.fromElf(image), image,
                        model, TaskMonitor.DUMMY, ignored -> { });
                    require(output.functions().stream().allMatch(f -> f.debuggerCallsDisabled()) == !match,
                        "language/compiler mismatch allowed");
                    if (match) require(output == model, "matching program knowledge changed");
                }
                finally { program.release(owner); }
            }
        }
        require(!MipsWideCallPolicy.programRestriction(image, correct, "unknown", () -> false).isEmpty(), "unknown compiler accepted");
    }

    private static void verify(ProgramTypeModel before, ProgramTypeModel after, boolean profile) {
        require(after.variableStorage() == before.variableStorage() && after.classScopes() == before.classScopes() &&
            after.functionRelations() == before.functionRelations(), "ownership or storage changed");
        for (int index = 0; index < CASES.size(); index++) {
            var selected = CASES.get(index);
            var original = before.functions().get(index);
            var function = after.functions().get(index);
            boolean blocked = !profile || !selected.allowed() || !selected.existing().isEmpty();
            require(function.debuggerCallsDisabled() == blocked, "wrong transfer decision " + selected);
            require(function.debuggerCallRestriction().startsWith(original.debuggerCallRestriction()), "existing restriction lost");
            require(original.equals(new FunctionSignature(function.name(), function.address(), function.returnType(),
                function.parameters(), function.locals(), function.variadic(), function.noReturn(), function.callingConvention(),
                function.signatureSource(), function.nonDefaultCallingConvention(), original.debuggerCallRestriction())), "signature changed");
            require(after.functionDeclarations().get(index).debuggerCallsDisabled() == blocked, "declaration bypass");
            var callback = (SubroutineType) after.types().byKey().get("callback" + index);
            require(callback.debuggerCallsDisabled() == blocked, "callback bypass");
        }
    }

    private static ElfBuildIdFixtures.Fixture fixture(Path path, boolean elf64, ByteOrder order, int carrier) throws Exception {
        byte[] record = ByteBuffer.allocate(24).order(order).putShort((short) 0)
            .put(new byte[] { 64, 2, 2, 2, 0, 1 }).putInt(0).putInt(0).putInt(1).putInt(0).array();
        var fixture = ElfBuildIdFixtures.create(path, elf64, order, record,
            (carrier & 1) != 0 ? List.of(new ElfBuildIdFixtures.View(0, 24, 8, 0x7000002a, 2)) : List.of(),
            (carrier & 2) != 0 ? List.of(new ElfBuildIdFixtures.View(0, 24, 8, 0x70000003, 4)) : List.of(),
            false, false, false, 0);
        fixture.patch(18, 2, 8);
        fixture.patch(elf64 ? 48 : 36, 4, elf64 ? 0x80000007L : 0x80000027L);
        return fixture;
    }

    private static ProgramTypeModel model(int pointerBytes) {
        var word = new TypeRef("word");
        var pair = new AggregateType("pair", "Pair", 16, AggregateKind.STRUCTURE,
            List.of(new Member("first", word, 0), new Member("second", word, 8)));
        var nodes = new ArrayList<TypeNode>(List.of(new VoidType("v"),
            new BaseType("i", "int", 4, BaseEncoding.SIGNED), new BaseType("word", "word", 8, BaseEncoding.SIGNED),
            new BaseType("f", "float", 4, BaseEncoding.FLOAT), new BaseType("d", "double", 8, BaseEncoding.FLOAT),
            new BaseType("quad", "long double", 16, BaseEncoding.FLOAT), pair,
            new AggregateType("large", "Large", 24, AggregateKind.STRUCTURE,
                List.of(new Member("first", word, 0), new Member("second", word, 8), new Member("third", word, 16))),
            new TypedefType("alias", "alias", 16, new TypeRef("pair")),
            new QualifiedType("qualified", "const alias", 16, List.of(Qualifier.CONST), new TypeRef("alias")),
            new IndirectionType("p", "word *", pointerBytes, IndirectionKind.POINTER, word),
            new IndirectionType("wrongPointer", "wrong pointer", 12 - pointerBytes, IndirectionKind.POINTER, word),
            new IndirectionType("reference", "word &", pointerBytes, IndirectionKind.LVALUE_REFERENCE, word),
            new EnumType("enum", "enum", 4, true, List.of(new Enumerator("one", 1))),
            new TypedefType("cycle1", "cycle1", 8, new TypeRef("cycle2")),
            new TypedefType("cycle2", "cycle2", 8, new TypeRef("cycle1")),
            new TypedefType("aliasBadSize", "wrong size", 4, word),
            new OpaqueType("opaque", "unknown", 8, "unresolved"),
            new AggregateType("union", "Union", 16, AggregateKind.UNION, pair.members()),
            new AggregateType("padded", "Padded", 24, AggregateKind.STRUCTURE, pair.members()),
            new AggregateType("overlap", "Overlap", 16, AggregateKind.STRUCTURE,
                List.of(new Member("a", word, 0), new Member("b", word, 0))),
            new AggregateType("fpPair", "FpPair", 16, AggregateKind.STRUCTURE,
                List.of(new Member("a", new TypeRef("d"), 0), new Member("b", new TypeRef("d"), 8))),
            new AggregateType("bits", "Bits", 16, AggregateKind.STRUCTURE,
                List.of(new Member("a", word, 0, 3, 0, 8), new Member("b", word, 8))),
            new AggregateType("nested", "Nested", 16, AggregateKind.STRUCTURE,
                List.of(new Member("a", new TypeRef("pair"), 0))),
            new ArrayType("array", "words", 16, word, 2),
            new AggregateType("huge", "Huge", 32, AggregateKind.STRUCTURE, pair.members())));
        var functions = new ArrayList<FunctionSignature>();
        var declarations = new ArrayList<FunctionDeclaration>();
        for (int index = 0; index < CASES.size(); index++) {
            var selected = CASES.get(index);
            var result = new TypeRef(selected.result());
            var parameters = List.of(new Parameter("arg", new TypeRef(selected.argument()), false));
            functions.add(new FunctionSignature("function" + index, 0x1000 + index * 16, result, parameters,
                List.of(), selected.variadic(), false, "default", "USER_DEFINED", false, selected.existing()));
            declarations.add(new FunctionDeclaration("external" + index, "external" + String.format("%02d", index), result, parameters,
                selected.variadic(), false, "default", "USER_DEFINED", false, selected.existing()));
            nodes.add(new SubroutineType("callback" + index, "callback" + index, 0, result, parameters,
                selected.variadic(), "default", selected.existing()));
        }
        return ghidradwarfforge.types.FunctionRelationsSmoke.withRelations(
            ghidradwarfforge.types.ClassScopeModelSmoke.withOwnership(new ProgramTypeModel(new TypeGraph(nodes),
                functions, List.of(), new VariableStorageModel(List.of()), List.of(), declarations)));
    }

    private static void require(boolean value, String message) {
        checks++;
        if (!value) throw new AssertionError(message);
    }
}
