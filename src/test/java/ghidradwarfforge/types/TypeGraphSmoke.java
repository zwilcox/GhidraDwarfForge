package ghidradwarfforge.types;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel;
import ghidradwarfforge.locations.VariableStorageModel.Confidence;
import ghidradwarfforge.locations.VariableStorageModel.Evidence;
import ghidradwarfforge.locations.VariableStorageModel.LocationRange;
import ghidradwarfforge.locations.VariableStorageModel.VariableKind;
import ghidradwarfforge.locations.VariableStorageModel.VariableLocation;
import ghidradwarfforge.types.TypeGraph.AggregateKind;
import ghidradwarfforge.types.TypeGraph.AggregateType;
import ghidradwarfforge.types.TypeGraph.ArrayType;
import ghidradwarfforge.types.TypeGraph.BaseEncoding;
import ghidradwarfforge.types.TypeGraph.BaseType;
import ghidradwarfforge.types.TypeGraph.EnumType;
import ghidradwarfforge.types.TypeGraph.Enumerator;
import ghidradwarfforge.types.TypeGraph.IndirectionKind;
import ghidradwarfforge.types.TypeGraph.IndirectionType;
import ghidradwarfforge.types.TypeGraph.Member;
import ghidradwarfforge.types.TypeGraph.OpaqueType;
import ghidradwarfforge.types.TypeGraph.Parameter;
import ghidradwarfforge.types.TypeGraph.QualifiedType;
import ghidradwarfforge.types.TypeGraph.Qualifier;
import ghidradwarfforge.types.TypeGraph.SubroutineType;
import ghidradwarfforge.types.TypeGraph.TypeNode;
import ghidradwarfforge.types.TypeGraph.TypeRef;
import ghidradwarfforge.types.TypeGraph.TypedefType;
import ghidradwarfforge.types.TypeGraph.VoidType;
import ghidradwarfforge.types.ProgramTypeModel.GlobalVariable;
import ghidradwarfforge.types.ProgramTypeModel.FunctionSignature;
import ghidradwarfforge.types.ProgramTypeModel.LocalVariable;

/** Native-free canonicalization and recursive-type smoke test. */
public final class TypeGraphSmoke {
    private TypeGraphSmoke() {
    }

    public static void main(String[] args) {
        TypeRef voidType = new TypeRef("builtin:void");
        TypeRef signedInt = new TypeRef("builtin:int32");
        TypeRef node = new TypeRef("fixture:node");
        TypeRef nodePointer = new TypeRef("fixture:node*");
        List<TypeNode> input = new ArrayList<>(List.of(
            new VoidType(voidType.key()),
            new BaseType(signedInt.key(), "int", 4, BaseEncoding.SIGNED),
            new IndirectionType(nodePointer.key(), "node *", 8,
                IndirectionKind.POINTER, node),
            new AggregateType(node.key(), "node", 16, AggregateKind.STRUCTURE,
                List.of(new Member("value", signedInt, 0),
                    new Member("next", nodePointer, 8),
                    new Member("flags", signedInt, 12, 3, 1))),
            new ArrayType("fixture:int[3]", "int[3]", 12, signedInt, 3),
            new EnumType("fixture:mode", "mode", 4, true,
                List.of(new Enumerator("MODE_NEGATIVE", -1),
                    new Enumerator("MODE_READY", 7))),
            new QualifiedType("fixture:const-node-pointer", "node * const", 8,
                List.of(Qualifier.VOLATILE, Qualifier.CONST, Qualifier.CONST),
                nodePointer),
            new TypedefType("fixture:node-handle", "node_handle", 8,
                new TypeRef("fixture:const-node-pointer")),
            new OpaqueType("fixture:dynamic", "dynamic_value", 0,
                "fixture unsupported dynamic type"),
            new SubroutineType("fixture:callback", "callback", 0, signedInt,
                List.of(new Parameter("item", nodePointer, false),
                    new Parameter("again", nodePointer, false)), true)));
        TypeGraph first = new TypeGraph(input);
        Collections.reverse(input);
        TypeGraph second = new TypeGraph(input);
        if (!first.equals(second)) {
            throw new AssertionError("type graph ordering is not deterministic");
        }
        AggregateType recursive = (AggregateType) first.byKey().get(node.key());
        if (!recursive.members().get(1).type().equals(nodePointer) ||
                recursive.members().get(2).bitSize() != 3 ||
                recursive.members().get(2).storageBitOffset() != 1 ||
                first.nodes().stream().map(TypeNode::key).distinct().count() !=
                    first.nodes().size()) {
            throw new AssertionError("recursive/canonical type identity failed");
        }
        SubroutineType callback = (SubroutineType) first.byKey().get("fixture:callback");
        if (!callback.variadic() ||
                !callback.parameters().get(0).type().equals(
                    callback.parameters().get(1).type())) {
            throw new AssertionError("repeated type reference was not canonical");
        }
        QualifiedType qualified = (QualifiedType) first.byKey().get(
            "fixture:const-node-pointer");
        if (!qualified.qualifiers().equals(List.of(Qualifier.CONST,
                Qualifier.VOLATILE))) {
            throw new AssertionError("qualifiers were not canonicalized");
        }
        FunctionSignature signature = new FunctionSignature("fixture", 0x800,
            signedInt, List.of(), List.of(
                new LocalVariable("later", 4, signedInt, 12, true, "ANALYSIS"),
                new LocalVariable("analyst_local", 4, signedInt, 0, false,
                    "USER_DEFINED")), false, false, "default", "USER_DEFINED");
        VariableLocation analystLocation = new VariableLocation("fixture", 0x800,
            "analyst_local", VariableKind.LOCAL, 4, List.of(new LocationRange(0x800,
                0x840, TargetRegisterMap.forTarget("x86_64").register("RAX", 0, 32),
                new Evidence(Confidence.USER_DEFINED, "type graph smoke"))));
        ProgramTypeModel program = new ProgramTypeModel(first, List.of(signature), List.of(
            new GlobalVariable("later", 0x2000, 4, signedInt, false, "ANALYSIS"),
            new GlobalVariable("declaration", 0x1000, 4, signedInt, true,
                "USER_DEFINED", List.of("outer", "inner"))),
            new VariableStorageModel(List.of(analystLocation)));
        if (!program.globals().get(0).name().equals("declaration") ||
                !program.globals().get(0).declaration() ||
                !program.globals().get(0).namespace().equals(List.of("outer", "inner")) ||
                !program.functions().get(0).locals().get(0).name().equals("analyst_local") ||
                !program.variableStorage().variables().get(0).equals(analystLocation)) {
            throw new AssertionError("global variable model is not deterministic");
        }
        try {
            new TypeGraph(List.of(new IndirectionType("bad", "bad *", 8,
                IndirectionKind.POINTER, new TypeRef("missing"))));
            throw new AssertionError("dangling type reference was accepted");
        }
        catch (IllegalArgumentException expected) {
            // Expected validation path.
        }
        System.out.println("type-graph-smoke=PASS");
    }
}
