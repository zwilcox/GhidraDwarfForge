package ghidradwarfforge.types;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.LongFunction;

import ghidradwarfforge.types.TypeGraph.*;

/** Producer model contracts: storage widths, value bytes, references and ownership. */
public final class TypeGraphBoundarySmoke {
    private static final TypeRef INT = new TypeRef("int");
    private static int checks;

    private TypeGraphBoundarySmoke() { }

    public static void main(String[] args) {
        run();
    }

    public static void run() {
        checks = 0;
        memberStorage();
        baseValues();
        parameterRoles();
        requiredFields();
        graphReferences();
        ownership();
        System.out.println("type-graph-boundaries=PASS checks=" + checks);
    }

    private static void memberStorage() {
        for (int bytes : new int[] {1, 2, 4, 8}) {
            int bits = bytes * 8;
            for (int offset = 0; offset <= bits + 1; offset++) {
                for (int width = 1; width <= bits + 1; width++) {
                    int selectedOffset = offset, selectedWidth = width;
                    // Independent half-open bit interval in the component's storage.
                    boolean fits = width <= bits && offset <= bits - width;
                    String label = "field " + bytes + "/" + offset + "/" + width;
                    if (!fits) {
                        rejected(label, () -> new Member("field", INT, 7, selectedWidth, selectedOffset, bytes));
                    }
                    else {
                        var member = new Member("field", INT, 7, width, offset, bytes);
                        require(member.byteOffset() == 7 && member.bitSize() == width &&
                            member.storageBitOffset() == offset && member.storageByteSize() == bytes &&
                            member.type().equals(INT), label + " changed accepted layout");
                    }
                }
            }
        }
        require(new Member("ordinary", INT, Long.MAX_VALUE).bitSize() == 0,
            "ordinary member byte offset narrowed");
        rejected("member type", () -> new Member("field", null, 0));
        rejected("negative byte offset", () -> new Member("field", INT, -1));
        rejected("negative bit width", () -> new Member("field", INT, 0, -1, 0, 1));
        rejected("negative bit offset", () -> new Member("field", INT, 0, 1, -1, 1));
        rejected("negative component size", () -> new Member("field", INT, 0, 1, 0, -1));
        rejected("ordinary bit offset", () -> new Member("field", INT, 0, 0, 1, 0));
        rejected("ordinary component size", () -> new Member("field", INT, 0, 0, 0, 1));
        rejected("missing component storage", () -> new Member("field", INT, 0, 1, 0, 0));
        rejected("overflowed bit interval", () -> new Member("field", INT, 0, 1, Integer.MAX_VALUE, 1));
        var wide = new Member("wide", INT, 0, Integer.MAX_VALUE, Integer.MAX_VALUE, 1 << 29);
        require(wide.storageByteSize() == 1 << 29 && wide.bitSize() == Integer.MAX_VALUE,
            "wide model interval narrowed");
    }

    private static void baseValues() {
        for (var encoding : BaseEncoding.values()) {
            for (int objectBytes : new int[] {1, 2, 4, 8, 16}) {
                for (int valueBytes = 0; valueBytes <= objectBytes + 1; valueBytes++) {
                    int selected = valueBytes;
                    boolean valid = encoding == BaseEncoding.FLOAT ?
                        valueBytes >= 1 && valueBytes <= objectBytes : valueBytes == objectBytes;
                    String label = "base value " + encoding + "/" + objectBytes + "/" + valueBytes;
                    if (!valid) rejected(label, () -> new BaseType("base", "base", objectBytes, encoding, selected));
                    else {
                        var type = new BaseType("base", "base", objectBytes, encoding, valueBytes);
                        var graph = new TypeGraph(List.of(type));
                        require(type.byteSize() == objectBytes && graph.valueByteSize(new TypeRef("base")) == valueBytes,
                            label + " confused object padding and value size");
                    }
                }
            }
        }
        rejected("base encoding", () -> new BaseType("int", "int", 4, null));
    }

    private static void parameterRoles() {
        // Bits: artificial=4, return storage=2, object pointer=1. Only these
        // semantic roles are legal: ordinary, artificial, hidden return, this.
        for (int flags = 0; flags < 8; flags++) {
            boolean artificial = (flags & 4) != 0, result = (flags & 2) != 0, object = (flags & 1) != 0;
            if (!List.of(0, 4, 6, 5).contains(flags)) {
                rejected("parameter roles " + flags, () -> new Parameter("arg", INT, artificial, result, object));
            }
            else {
                var parameter = new Parameter("", INT, artificial, result, object);
                require(parameter.name().isEmpty() && parameter.type().equals(INT) &&
                    parameter.artificial() == artificial && parameter.returnStorage() == result &&
                    parameter.objectPointer() == object, "parameter role changed");
            }
        }
        rejected("parameter name", () -> new Parameter(null, INT, false));
        rejected("parameter type", () -> new Parameter("arg", null, false));
    }

    private static void requiredFields() {
        for (String text : Arrays.asList(null, "", " \n ")) {
            rejected("reference text", () -> new TypeRef(text));
            rejected("type key", () -> new BaseType(text, "int", 4, BaseEncoding.SIGNED));
            rejected("type name", () -> new BaseType("int", text, 4, BaseEncoding.SIGNED));
            rejected("opaque diagnostic", () -> new OpaqueType("opaque", "opaque", 0, text));
        }
        rejected("indirection kind", () -> new IndirectionType("p", "p", 8, null, INT));
        rejected("indirection target", () -> new IndirectionType("p", "p", 8, IndirectionKind.POINTER, null));
        rejected("qualified target", () -> new QualifiedType("q", "q", 4, List.of(Qualifier.CONST), null));
        rejected("null qualifiers", () -> new QualifiedType("q", "q", 4, null, INT));
        rejected("empty qualifiers", () -> new QualifiedType("q", "q", 4, List.of(), INT));
        rejected("array element", () -> new ArrayType("a", "a", 0, null, 0));
        rejected("array count", () -> new ArrayType("a", "a", 0, INT, -1));
        rejected("typedef target", () -> new TypedefType("t", "t", 0, null));
        rejected("aggregate kind", () -> new AggregateType("s", "s", 0, null, List.of()));
        rejected("return type", () -> new SubroutineType("f", "f", 0, null, List.of(), false));
        rejected("calling convention", () -> new SubroutineType("f", "f", 0, INT, List.of(), false, null, ""));
        rejected("call restriction", () -> new SubroutineType("f", "f", 0, INT, List.of(), false, "", null));
        List<LongFunction<TypeNode>> positiveSize = List.of(
            size -> new BaseType("b", "b", size, BaseEncoding.SIGNED),
            size -> new IndirectionType("p", "p", size, IndirectionKind.POINTER, INT),
            size -> new EnumType("e", "e", size, false, List.of()));
        List<LongFunction<TypeNode>> zeroAllowed = List.of(
            size -> new QualifiedType("q", "q", size, List.of(Qualifier.CONST), INT),
            size -> new ArrayType("a", "a", size, INT, 0),
            size -> new TypedefType("t", "t", size, INT),
            size -> new AggregateType("s", "s", size, AggregateKind.STRUCTURE, List.of()),
            size -> new SubroutineType("f", "f", size, INT, List.of(), false),
            size -> new OpaqueType("o", "o", size, "unknown layout"));
        for (var factory : positiveSize) {
            rejected("negative object size", () -> factory.apply(-1));
            rejected("zero scalar size", () -> factory.apply(0));
            require(factory.apply(1).byteSize() == 1, "positive size rejected");
        }
        for (var factory : zeroAllowed) {
            rejected("negative object size", () -> factory.apply(-1));
            require(factory.apply(0).byteSize() == 0, "zero-sized declaration rejected");
        }
    }

    private static void graphReferences() {
        var integer = new BaseType("int", "int", 4, BaseEncoding.SIGNED);
        rejected("null graph", () -> new TypeGraph(null));
        rejected("null node", () -> new TypeGraph(Arrays.asList(integer, null)));
        rejected("duplicate key", () -> new TypeGraph(List.of(integer, new VoidType("int"))));
        require(new TypeGraph(List.of()).nodes().isEmpty(), "empty graph rejected");
        var graph = new TypeGraph(List.of(new BaseType("float", "long double", 16, BaseEncoding.FLOAT, 10),
            new QualifiedType("qualified", "qualified", 16, List.of(Qualifier.CONST), new TypeRef("float")),
            new TypedefType("alias", "alias", 16, new TypeRef("qualified")),
            new IndirectionType("pointer", "pointer", 8, IndirectionKind.POINTER, new TypeRef("alias"))));
        require(graph.valueByteSize(new TypeRef("alias")) == 10, "alias/qualifier lost floating value width");
        require(graph.valueByteSize(new TypeRef("pointer")) == 8, "pointer chased pointee value width");
        rejected("missing value reference", () -> graph.valueByteSize(INT));
        var self = new TypeGraph(List.of(new TypedefType("self", "self", 4, new TypeRef("self"))));
        rejected("self alias cycle", () -> self.valueByteSize(new TypeRef("self")));
        var cycle = new TypeGraph(List.of(new TypedefType("alias", "alias", 4, new TypeRef("qualified")),
            new QualifiedType("qualified", "qualified", 4, List.of(Qualifier.CONST), new TypeRef("alias"))));
        rejected("alias qualifier cycle", () -> cycle.valueByteSize(new TypeRef("alias")));
        for (var kind : IndirectionKind.values()) {
            var recursive = new TypeGraph(List.of(new IndirectionType("self", "self", 8, kind, new TypeRef("self"))));
            require(recursive.valueByteSize(new TypeRef("self")) == 8, "recursive pointer/reference lost own size");
        }
    }

    private static void ownership() {
        var members = new ArrayList<>(List.of(new Member("value", INT, 0)));
        var aggregate = new AggregateType("record", "record", 4, AggregateKind.STRUCTURE, members);
        members.clear();
        require(aggregate.members().size() == 1 && aggregate.references().equals(List.of(INT)), "members alias caller list");
        var qualifiers = new ArrayList<>(List.of(Qualifier.VOLATILE, Qualifier.CONST, Qualifier.VOLATILE));
        var qualified = new QualifiedType("q", "q", 4, qualifiers, INT);
        qualifiers.clear();
        require(qualified.qualifiers().equals(List.of(Qualifier.CONST, Qualifier.VOLATILE)), "qualifiers not canonical");
        var input = new ArrayList<TypeNode>(List.of(aggregate, new BaseType("int", "int", 4, BaseEncoding.SIGNED)));
        var graph = new TypeGraph(input);
        input.clear();
        require(graph.nodes().stream().map(TypeNode::key).toList().equals(List.of("int", "record")),
            "graph storage/order aliases caller list");
        immutable(() -> graph.nodes().clear());
        for (var node : graph.nodes()) {
            if (graph.lookup(node.key()) != node) throw new AssertionError("incorrect canonical type lookup");
        }
        if (graph.lookup("") != null || graph.lookup("absent") != null || graph.lookup("\uffff") != null) {
            throw new AssertionError("missing reference mapped to an unrelated type");
        }
        immutable(() -> graph.byKey().remove("int"));
        immutable(() -> aggregate.members().clear());
        immutable(() -> aggregate.references().clear());
        immutable(() -> qualified.qualifiers().clear());
    }

    private static void rejected(String label, Runnable action) {
        checks++;
        try { action.run(); }
        catch (IllegalArgumentException expected) { return; }
        throw new AssertionError("invalid type model accepted: " + label);
    }

    private static void immutable(Runnable action) {
        checks++;
        try { action.run(); }
        catch (UnsupportedOperationException expected) { return; }
        throw new AssertionError("type model collection is mutable");
    }

    private static void require(boolean condition, String detail) {
        checks++;
        if (!condition) throw new AssertionError(detail);
    }
}
