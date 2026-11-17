package ghidradwarfforge.elf;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import ghidradwarfforge.locations.VariableStorageModel;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.ProgramTypeModel.FunctionDeclaration;
import ghidradwarfforge.types.ProgramTypeModel.FunctionSignature;
import ghidradwarfforge.types.TypeGraph;
import ghidradwarfforge.types.TypeGraph.*;

/** All callable forms must conservatively classify bounded, explicit type graphs. */
public final class ArmCallSignatureBoundarySmoke {
    private static int checks;
    private static final TypeRef VOID = new TypeRef("void");
    private static final TypeRef INTEGER = new TypeRef("integer");
    private static final String CONVENTION = "__stdcall_softfp";

    public static void main(String[] args) throws Exception {
        var path = Files.createTempFile("forge-arm-call-signatures-", ".elf");
        try {
            for (var order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                var bytes = ByteBuffer.allocate(52).order(order);
                bytes.put(new byte[] {0x7f, 'E', 'L', 'F', 1, (byte) (order == ByteOrder.LITTLE_ENDIAN ? 1 : 2), 1});
                bytes.putShort(16, (short) 2).putShort(18, (short) 40).putInt(20, 1);
                bytes.putInt(36, 0x05000000 | (order == ByteOrder.BIG_ENDIAN ? 0x800000 : 0)).putShort(40, (short) 52);
                Files.write(path, bytes.array());
                run(ElfImage.read(path));
            }
        }
        finally { Files.deleteIfExists(path); }
    }

    static void run(ElfImage image) throws Exception {
        require(Arm32CallAbi.observe(image, () -> false).consumer() == Arm32CallAbi.Pcs.BASE,
            "fixture consumer uses base PCS");
        for (int count : new int[] {0, 1, 4096, 4097}) {
            var parameters = new ArrayList<Parameter>();
            for (int index = 0; index < count; index++) parameters.add(new Parameter("input" + index, INTEGER, false));
            check(image, nodes(), VOID, parameters, count > 4096, "parameter count " + count, "");
        }
        for (int depth : new int[] {1, 64, 65}) {
            var nodes = nodes();
            TypeRef type = INTEGER;
            for (int index = 0; index < depth; index++) {
                String key = "wrapper" + index;
                nodes.add(index % 2 == 0 ? new TypedefType(key, key, 4, type) :
                    new QualifiedType(key, key, 4, List.of(Qualifier.CONST), type));
                type = new TypeRef(key);
            }
            check(image, nodes, VOID, List.of(new Parameter("wrapped", type, false)), depth > 64, "wrapper depth " + depth, "");
        }
        for (var encoding : BaseEncoding.values()) {
            for (int width : new int[] {1, 2, 3, 4, 8, 16}) {
                var nodes = nodes();
                nodes.add(new BaseType("scalar", "scalar", width, encoding));
                boolean accepted = encoding == BaseEncoding.FLOAT ? width == 4 || width == 8 : width == 1 || width == 2 || width == 4 || width == 8;
                check(image, nodes, VOID, List.of(new Parameter("scalar", new TypeRef("scalar"), false)),
                    !accepted, encoding + "/" + width, "");
            }
        }
        for (int width : new int[] {1, 2, 3, 4, 8, 16}) {
            var nodes = nodes();
            nodes.add(new EnumType("enum", "enum", width, false, List.of(new Enumerator("ONE", 1))));
            check(image, nodes, VOID, List.of(new Parameter("enum", new TypeRef("enum"), false)),
                width == 3 || width == 16, "enum width " + width, "");
            nodes.add(new IndirectionType("pointer", "integer *", width, IndirectionKind.POINTER, INTEGER));
            check(image, nodes, VOID, List.of(new Parameter("pointer", new TypeRef("pointer"), false)),
                width != 4, "pointer width " + width, "");
        }
        aggregates(image);
        hiddenReturns(image);
        check(image, nodes(), VOID, List.of(new Parameter("unknown_auto", INTEGER, true)), true, "unknown automatic role", "");
        check(image, nodes(), VOID, List.of(new Parameter("integer", INTEGER, false)), false, "independent restriction", "analyst call restriction");
        System.out.println("arm-call-signature-boundaries=PASS checks=" + checks);
    }

    private static void aggregates(ElfImage image) throws Exception {
        for (String layout : List.of("empty", "four", "five", "tail_padding", "short_field", "enum_field", "mixed_float_widths", "unaligned_tail")) {
            var nodes = nodes();
            nodes.add(new BaseType("short", "short", 2, BaseEncoding.SIGNED));
            nodes.add(new BaseType("float", "float", 4, BaseEncoding.FLOAT));
            nodes.add(new BaseType("double", "double", 8, BaseEncoding.FLOAT));
            nodes.add(new EnumType("enum", "enum", 4, true, List.of(new Enumerator("ONE", 1))));
            var members = new ArrayList<Member>();
            long size;
            switch (layout) {
                case "four", "five" -> {
                    int count = layout.equals("four") ? 4 : 5;
                    for (int index = 0; index < count; index++) members.add(new Member("field" + index, INTEGER, 4L * index));
                    size = count * 4L;
                }
                case "tail_padding" -> { members.add(new Member("field", INTEGER, 0)); size = 8; }
                case "short_field" -> { members.add(new Member("field", new TypeRef("short"), 0)); size = 2; }
                case "enum_field" -> { members.add(new Member("field", new TypeRef("enum"), 0)); size = 4; }
                case "mixed_float_widths", "unaligned_tail" -> {
                    members.add(new Member("wide", new TypeRef("double"), 0));
                    members.add(new Member("narrow", new TypeRef("float"), 8));
                    if (layout.equals("mixed_float_widths")) members.add(new Member("last", new TypeRef("float"), 12));
                    size = layout.equals("mixed_float_widths") ? 16 : 12;
                }
                default -> size = 4;
            }
            nodes.add(new AggregateType("aggregate", "aggregate", size, AggregateKind.STRUCTURE, members));
            check(image, nodes, VOID, List.of(new Parameter("aggregate", new TypeRef("aggregate"), false)),
                !List.of("four", "mixed_float_widths").contains(layout), layout, "");
            if (layout.equals("mixed_float_widths")) {
                check(image, nodes, VOID, List.of(new Parameter("aggregate", new TypeRef("aggregate"), false)),
                    false, "mixed floating widths retain base transfer under VFP selection", "", "__stdcall");
            }
        }
    }

    private static void hiddenReturns(ElfImage image) throws Exception {
        for (String mode : List.of("valid", "duplicate", "small_result", "scalar_result", "nonpointer", "wide_pointer", "reference_carrier")) {
            var nodes = nodes();
            var aggregate = new TypeRef("aggregate");
            var members = new ArrayList<>(List.of(new Member("first", INTEGER, 0)));
            if (!mode.equals("small_result")) members.add(new Member("second", INTEGER, 4));
            nodes.add(new AggregateType("aggregate", "aggregate", members.size() * 4L, AggregateKind.STRUCTURE, members));
            nodes.add(new IndirectionType("carrier", "aggregate *", mode.equals("wide_pointer") ? 8 : 4,
                mode.equals("reference_carrier") ? IndirectionKind.LVALUE_REFERENCE : IndirectionKind.POINTER, aggregate));
            var parameters = new ArrayList<>(List.of(new Parameter("result", mode.equals("nonpointer") ? INTEGER : new TypeRef("carrier"), true, true)));
            if (mode.equals("duplicate")) parameters.add(new Parameter("second_result", new TypeRef("carrier"), true, true));
            check(image, nodes, mode.equals("scalar_result") ? INTEGER : aggregate, parameters,
                !mode.equals("valid"), "hidden " + mode, "");
        }
    }

    private static ArrayList<TypeNode> nodes() {
        return new ArrayList<>(List.of(new VoidType("void"), new BaseType("integer", "int", 4, BaseEncoding.SIGNED)));
    }

    private static void check(ElfImage image, List<TypeNode> sourceNodes, TypeRef returned, List<Parameter> parameters,
            boolean blocked, String label, String previousRestriction) throws Exception {
        check(image, sourceNodes, returned, parameters, blocked, label, previousRestriction, CONVENTION);
    }

    private static void check(ElfImage image, List<TypeNode> sourceNodes, TypeRef returned, List<Parameter> parameters,
            boolean blocked, String label, String previousRestriction, String convention) throws Exception {
        var nodes = new ArrayList<>(sourceNodes);
        nodes.add(new SubroutineType("callback", "callback", 0, returned, parameters, false, convention, previousRestriction, false));
        var input = new ProgramTypeModel(new TypeGraph(nodes),
            List.of(new FunctionSignature("function", 0x1000, returned, parameters, List.of(), false, false,
                convention, "USER_DEFINED", false, previousRestriction)), List.of(), new VariableStorageModel(List.of()), List.of(),
            List.of(new FunctionDeclaration("external", "declared", returned, parameters, false, false, convention,
                "USER_DEFINED", false, previousRestriction)));
        String before = input.toString();
        var output = Arm32CallPolicy.apply(image, input, () -> false, ignored -> { });
        var function = output.functions().getFirst();
        var declaration = output.functionDeclarations().getFirst();
        var callback = (SubroutineType) output.types().byKey().get("callback");
        boolean disabled = blocked || !previousRestriction.isEmpty();
        require(function.debuggerCallsDisabled() == disabled && declaration.debuggerCallsDisabled() == disabled &&
            callback.debuggerCallsDisabled() == disabled, label + ": callable forms must agree");
        require(function.returnType().equals(returned) && declaration.returnType().equals(returned) && callback.returnType().equals(returned) &&
            function.parameters().equals(parameters) && declaration.parameters().equals(parameters) && callback.parameters().equals(parameters),
            label + ": classification preserves all recovered formal types and parameters");
        require(function.debuggerCallRestriction().contains(previousRestriction) && declaration.debuggerCallRestriction().contains(previousRestriction) &&
            callback.debuggerCallRestriction().contains(previousRestriction), label + ": independent restrictions survive");
        require(input.toString().equals(before), label + ": input graph remains unchanged");
        require(output.equals(Arm32CallPolicy.apply(image, output, () -> false, ignored -> { })), label + ": classification is idempotent");
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }
}
