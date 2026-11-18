package ghidradwarfforge.elf;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import ghidradwarfforge.locations.VariableStorageModel;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.ProgramTypeModel.FunctionDeclaration;
import ghidradwarfforge.types.ProgramTypeModel.FunctionSignature;
import ghidradwarfforge.types.TypeGraph;
import ghidradwarfforge.types.TypeGraph.*;

/** N32/N64 callable forms must agree on bounded aliases and explicit transfer evidence. */
public final class MipsWideSignatureBoundarySmoke {
    private static final TypeRef VOID = new TypeRef("void");
    private static final TypeRef WORD = new TypeRef("word");
    private static int checks;

    public static void main(String[] args) throws Exception {
        var root = Files.createTempDirectory("forge-mips-signatures-");
        try {
            for (boolean wide : List.of(false, true)) {
                for (var order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                    byte[] record = ByteBuffer.allocate(24).order(order).putShort((short) 0)
                        .put(new byte[] {64, 2, 2, 2, 0, 1}).putInt(0).putInt(0).putInt(1).putInt(0).array();
                    var fixture = ElfBuildIdFixtures.create(root.resolve("input"), wide, order, record,
                        List.of(new ElfBuildIdFixtures.View(0, 24, 8, 0x7000002a, 2)), List.of(), false, false, false, 0);
                    fixture.patch(18, 2, 8);
                    fixture.patch(wide ? 48 : 36, 4, wide ? 0x80000007L : 0x80000027L);
                    run(ElfImage.read(fixture.path()));
                }
            }
        }
        finally {
            try (var paths = Files.walk(root)) {
                for (var path : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
    }

    static void run(ElfImage image) throws Exception {
        require(MipsWideCallPolicy.metadataRestriction(image, () -> false).isEmpty(), "valid typed MIPS64r2 fixture");
        int pointerBytes = image.is64Bit() ? 8 : 4;
        for (int depth : new int[] {1, 64, 65}) {
            var nodes = nodes();
            TypeRef type = WORD;
            for (int index = 0; index < depth; index++) {
                String key = "wrapper" + index;
                nodes.add(index % 2 == 0 ? new TypedefType(key, key, 8, type) :
                    new QualifiedType(key, key, 8, List.of(Qualifier.CONST), type));
                type = new TypeRef(key);
            }
            check(image, nodes, type, List.of(new Parameter("wrapped", type, false)), depth > 64, "wrapper depth " + depth, "");
        }
        for (var encoding : BaseEncoding.values()) {
            for (int width : new int[] {1, 2, 3, 4, 8, 16}) {
                var nodes = nodes();
                nodes.add(new BaseType("scalar", "scalar", width, encoding));
                boolean integer = List.of(BaseEncoding.SIGNED, BaseEncoding.UNSIGNED, BaseEncoding.SIGNED_CHAR,
                    BaseEncoding.UNSIGNED_CHAR, BaseEncoding.BOOLEAN).contains(encoding);
                boolean accepted = encoding == BaseEncoding.FLOAT ? width == 4 || width == 8 : integer && width != 3 && width != 16;
                var scalar = new TypeRef("scalar");
                check(image, nodes, scalar, List.of(), !accepted, "result " + encoding + "/" + width, "");
                check(image, nodes, VOID, List.of(new Parameter("scalar", scalar, false)), !accepted, "argument " + encoding + "/" + width, "");
            }
        }
        for (int width : new int[] {1, 2, 3, 4, 8, 16}) {
            var nodes = nodes();
            nodes.add(new EnumType("enum", "enum", width, false, List.of(new Enumerator("ONE", 1))));
            var enumeration = new TypeRef("enum");
            check(image, nodes, enumeration, List.of(), width == 3 || width == 16, "enum result " + width, "");
            check(image, nodes, VOID, List.of(new Parameter("enum", enumeration, false)), width == 3 || width == 16, "enum parameter " + width, "");
            for (var kind : IndirectionKind.values()) {
                var pointers = new ArrayList<TypeNode>(nodes);
                pointers.add(new IndirectionType("pointer", "word pointer", width, kind, WORD));
                var pointer = new TypeRef("pointer");
                boolean blocked = kind != IndirectionKind.POINTER || width != pointerBytes;
                check(image, pointers, pointer, List.of(), blocked, "pointer result " + kind + "/" + width, "");
                check(image, pointers, VOID, List.of(new Parameter("pointer", pointer, false)), blocked, "pointer parameter " + kind + "/" + width, "");
            }
        }
        for (String field : List.of("word", "short", "enum", "pointer", "opaque")) {
            var nodes = nodes();
            nodes.add(new BaseType("short", "short", 2, BaseEncoding.SIGNED));
            nodes.add(new EnumType("enum", "enum", 8, false, List.of(new Enumerator("ONE", 1))));
            nodes.add(new IndirectionType("pointer", "word pointer", pointerBytes, IndirectionKind.POINTER, WORD));
            nodes.add(new OpaqueType("opaque", "unknown", 8, "no storage proof"));
            nodes.add(new AggregateType("aggregate", "aggregate", 16, AggregateKind.STRUCTURE,
                List.of(new Member("first", WORD, 0), new Member("last", new TypeRef(field), 8))));
            check(image, nodes, VOID, List.of(new Parameter("aggregate", new TypeRef("aggregate"), false)),
                !field.equals("word"), "aggregate field " + field, "");
        }
        hiddenReturns(image, pointerBytes);
        check(image, nodes(), VOID, List.of(new Parameter("unknown_auto", WORD, true)), true, "unknown automatic role", "");
        check(image, nodes(), VOID, List.of(), false, "independent restriction", "analyst call restriction");
        System.out.println("mips-wide-signature-boundaries=PASS checks=" + checks);
    }

    private static void hiddenReturns(ElfImage image, int pointerBytes) throws Exception {
        for (String scenario : List.of("valid", "duplicate", "scalar_result", "small_result", "scalar_carrier", "reference_carrier", "wrong_target", "wrong_width")) {
            var nodes = nodes();
            nodes.add(new AggregateType("pair", "pair", 16, AggregateKind.STRUCTURE,
                List.of(new Member("a", WORD, 0), new Member("b", WORD, 8))));
            nodes.add(new AggregateType("triple", "triple", 24, AggregateKind.STRUCTURE,
                List.of(new Member("a", WORD, 0), new Member("b", WORD, 8), new Member("c", WORD, 16))));
            var result = new TypeRef(scenario.equals("scalar_result") ? "word" : scenario.equals("small_result") ? "pair" : "triple");
            nodes.add(new IndirectionType("carrier", "result carrier", scenario.equals("wrong_width") ? 12 - pointerBytes : pointerBytes,
                scenario.equals("reference_carrier") ? IndirectionKind.LVALUE_REFERENCE : IndirectionKind.POINTER,
                scenario.equals("wrong_target") ? WORD : result));
            var hidden = new Parameter("return_storage", scenario.equals("scalar_carrier") ? WORD : new TypeRef("carrier"), true, true);
            check(image, nodes, result, scenario.equals("duplicate") ? List.of(hidden, hidden) : List.of(hidden),
                !scenario.equals("valid"), scenario, "");
        }
    }

    private static ArrayList<TypeNode> nodes() {
        return new ArrayList<>(List.of(new VoidType("void"), new BaseType("word", "word", 8, BaseEncoding.SIGNED)));
    }

    private static void check(ElfImage image, List<TypeNode> originalNodes, TypeRef returned, List<Parameter> parameters,
            boolean blocked, String label, String previousRestriction) throws Exception {
        var nodes = new ArrayList<>(originalNodes);
        nodes.add(new SubroutineType("callback", "callback", 0, returned, parameters, false, "default", previousRestriction));
        var input = new ProgramTypeModel(new TypeGraph(nodes),
            List.of(new FunctionSignature("function", 0x1000, returned, parameters, List.of(), false, false,
                "default", "USER_DEFINED", false, previousRestriction)), List.of(), new VariableStorageModel(List.of()), List.of(),
            List.of(new FunctionDeclaration("external", "declared", returned, parameters, false, false, "default",
                "USER_DEFINED", false, previousRestriction)));
        String before = input.toString();
        var output = MipsWideCallPolicy.apply(image, input, () -> false, ignored -> { });
        var function = output.functions().getFirst();
        var declaration = output.functionDeclarations().getFirst();
        var callback = (SubroutineType) output.types().byKey().get("callback");
        boolean disabled = blocked || !previousRestriction.isEmpty();
        require(function.debuggerCallsDisabled() == disabled && declaration.debuggerCallsDisabled() == disabled &&
            callback.debuggerCallsDisabled() == disabled, label + ": callable forms must agree");
        require(function.returnType().equals(returned) && declaration.returnType().equals(returned) && callback.returnType().equals(returned) &&
            function.parameters().equals(parameters) && declaration.parameters().equals(parameters) && callback.parameters().equals(parameters),
            label + ": preserve recovered formal types and parameters");
        require(function.debuggerCallRestriction().contains(previousRestriction) && declaration.debuggerCallRestriction().contains(previousRestriction) &&
            callback.debuggerCallRestriction().contains(previousRestriction), label + ": preserve independent restrictions");
        require(input.toString().equals(before), label + ": preserve input graph");
        require(output.equals(MipsWideCallPolicy.apply(image, output, () -> false, ignored -> { })), label + ": idempotent classification");
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }
}
