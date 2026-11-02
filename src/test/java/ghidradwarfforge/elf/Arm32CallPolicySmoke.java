package ghidradwarfforge.elf;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

import ghidradwarfforge.CompilerCallPolicySmoke;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.ProgramTypeModel.FunctionDeclaration;
import ghidradwarfforge.types.ProgramTypeModel.FunctionSignature;
import ghidradwarfforge.types.TypeGraph;
import ghidradwarfforge.types.TypeGraph.*;

/** Independent AAELF carriers and all callable forms, including malformed metadata. */
public final class Arm32CallPolicySmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Path path = Files.createTempFile("forge-arm-pcs-", ".elf");
        try {
            for (var order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                int endianFlag = order == ByteOrder.BIG_ENDIAN ? 0x800000 : 0;
                for (int floatingFlag : new int[] {0, 0x200, 0x400}) {
                    int flags = 0x05000000 | endianFlag | floatingFlag;
                    boolean hard = floatingFlag == 0x400;
                    int attribute = hard ? 1 : 0;
                    var elf = write(path, order, flags, attributes(order, 28, attribute));
                    var observed = Arm32CallAbi.observe(elf, () -> false);
                    require(observed.valid() && observed.attributesPresent(), "valid PCS attributes rejected");
                    require(observed.declared() == (hard ? Arm32CallAbi.Pcs.VFP : Arm32CallAbi.Pcs.BASE),
                        "declared PCS changed");
                    require(observed.consumer() == observed.declared(), "matching consumer changed");
                    policy(elf, hard);
                    var compatible = write(path, order, flags, attributes(order, 28, 3));
                    require(Arm32CallAbi.observe(compatible, () -> false).declared() == Arm32CallAbi.Pcs.COMPATIBLE,
                        "compatible-only attribute lost");
                    classified(compatible, "float", "__stdcall_softfp", false, "", true, true);
                    var absent = write(path, order, flags, null);
                    var missing = Arm32CallAbi.observe(absent, () -> false);
                    require(missing.valid() && !missing.attributesPresent() && missing.consumer() == Arm32CallAbi.Pcs.BASE,
                        "absent attributes invented a VFP consumer");
                    classified(absent, "float", "__stdcall_softfp", false, "", true, false);
                    classified(absent, "float", "__stdcall", false, "", false, true);
                    rejected(path, order, flags, attributes(order, 28, hard ? 0 : 1), "contradict");
                }
                int flags = 0x05000400 | endianFlag;
                for (int invalid : new int[] {0x600, 0x100, 0x800, 0x1000}) {
                    rejected(path, order, flags | invalid, attributes(order, 28, 1), "metadata");
                }
                for (int invalid : new int[] {2, 4, 127}) {
                    rejected(path, order, flags, attributes(order, 28, invalid), "floating PCS attribute");
                }
                rejected(path, order, flags, attributes(order, 28, 1, 28, 1), "duplicate");
                rejected(path, order, flags, attributes(order, 64, 0), "nodefaults");
                rejected(path, order, flags, attributes(order, 28, 1, 29, 1), "WMMX");
                rejected(path, order, flags, attributes(order, 28, 1, 54, 0), "mandatory");
                rejected(path, order, flags, attributes(order, 28, 1, 32, 1, 'x', 0), "compatibility");
                rejected(path, order, flags, attributes(order, 28, 128, 128, 128, 128, 16), "overflowing");
                rejected(path, order, flags, attributes(order, 28), "truncated");
                rejected(path, order, flags, attributes(order, 5, 'a'), "truncated");
                var optional = write(path, order, flags, attributes(order, 28, 1, 65, 'x', 0, 66, 3));
                require(Arm32CallAbi.observe(optional, () -> false).valid(), "optional attributes changed PCS");
                byte[] bytes = attributes(order, 28, 1);
                bytes[0] = 'B';
                rejected(path, order, flags, bytes, "format");
                bytes = attributes(order, 28, 1);
                ByteBuffer.wrap(bytes).order(order).putInt(1, -1);
                rejected(path, order, flags, bytes, "vendor extent");
                bytes = attributes(order, 28, 1);
                ByteBuffer.wrap(bytes).order(order).putInt(12, 4);
                rejected(path, order, flags, bytes, "scope extent");
                for (int scope : new int[] {2, 3}) {
                    bytes = attributes(order, 28, 1);
                    bytes[11] = (byte) scope;
                    rejected(path, order, flags, bytes, "scoped");
                }
                bytes = attributes(order, 28, 1);
                for (int length = 0; length < bytes.length; length++) {
                    var truncated = write(path, order, flags, Arrays.copyOf(bytes, length));
                    require(!Arm32CallAbi.observe(truncated, () -> false).valid(), "truncated attributes accepted");
                }
                var elf = write(path, order, flags, attributes(order, 28, 1));
                for (int stop : new int[] {0, 3, 9}) {
                    var remaining = new AtomicInteger(stop);
                    try {
                        Arm32CallAbi.observe(elf, () -> remaining.getAndDecrement() == 0);
                        throw new AssertionError("metadata cancellation ignored");
                    }
                    catch (CancellationException expected) { checks++; }
                }
            }
            // An actual GCC ARMv7 hard-float attribute record, independent of the fixture encoder.
            byte[] gcc = HexFormat.of().parseHex(
                "412e000000616561626900012400000005372d4100060a0741080109020a04120414011501170318011a021c012201");
            require(Arm32CallAbi.observe(write(path, ByteOrder.LITTLE_ENDIAN, 0x05000400, gcc),
                () -> false).valid(), "GCC hard-float attributes rejected");
        }
        finally { Files.delete(path); }
        System.out.println("arm32-call-policy=PASS checks=" + checks);
    }

    private static void policy(ElfImage elf, boolean hard) throws Exception {
        implicitDefault(elf, hard);
        for (String convention : List.of("__stdcall", "__stdcall_softfp", "default", "unregistered")) {
            boolean known = !convention.equals("unregistered");
            boolean selectedHard = convention.equals("__stdcall") || convention.equals("default");
            boolean unmapped = !convention.equals("default") && !convention.equals("__stdcall");
            for (String type : List.of("integer", "float", "double", "alias", "qualified", "pointer", "wide")) {
                boolean floating = List.of("float", "double", "alias", "qualified").contains(type);
                boolean blocked = !known || (floating && selectedHard != hard);
                classified(elf, type, convention, false, "", unmapped, blocked);
                classified(elf, type, convention, false, "independent compiler/custom restriction", unmapped, true);
            }
        }
        for (String type : List.of("cycle", "opaque", "array", "wide_pointer", "half", "bad_alias")) {
            classified(elf, type, "__stdcall", false, "", false, true);
        }
        aggregateReturns(elf);
        classified(elf, "float", "__stdcall_softfp", true, "", true, false);
        classified(elf, "float", "__stdcall", true, "", false, true);
        var input = model("float", "__stdcall", false, "", false);
        for (int stop : new int[] {0, 3, 20, 27}) {
            var remaining = new AtomicInteger(stop);
            try {
                Arm32CallPolicy.apply(elf, input, () -> remaining.getAndDecrement() == 0, message -> { });
                throw new AssertionError("policy cancellation ignored");
            }
            catch (CancellationException expected) { checks++; }
        }
    }

    private static void implicitDefault(ElfImage elf, boolean hard) throws Exception {
        var input = model("float", "unknown", false, "", false);
        var function = input.functions().getFirst();
        var declaration = input.functionDeclarations().getFirst();
        var functions = List.of(new FunctionSignature(function.name(), function.address(), function.returnType(),
            function.parameters(), function.locals(), false, false, "unknown", "USER_DEFINED", false, "", "__stdcall"),
            input.functions().get(1));
        var declarations = List.of(new FunctionDeclaration(declaration.key(), declaration.name(), declaration.returnType(),
            declaration.parameters(), false, false, "unknown", "USER_DEFINED", false, "", "__stdcall"));
        var dynamic = new ProgramTypeModel(input.types(), functions, input.globals(), input.variableStorage(),
            input.functionStatics(), declarations, input.lexicalScopes(), input.classScopes(), input.functionRelations());
        var output = Arm32CallPolicy.apply(elf, dynamic, () -> false, message -> { });
        require(output.functions().getFirst().debuggerCallsDisabled() == !hard &&
            output.functionDeclarations().getFirst().debuggerCallsDisabled() == !hard,
            "dynamic default PCS was not classified against the ELF consumer");
        require(output.functions().getFirst().callingConvention().equals("unknown") &&
            output.functionDeclarations().getFirst().callingConvention().equals("unknown"), "recorded unknown name rewritten");
        require(output.functions().getFirst().effectiveCallingConvention().equals("__stdcall") &&
            output.functionDeclarations().getFirst().effectiveCallingConvention().equals("__stdcall"), "effective model lost");
        require(((SubroutineType) output.types().byKey().get("callback")).debuggerCallsDisabled(),
            "unresolved function-pointer type borrowed an unrelated storage fallback");
        var blocked = ghidradwarfforge.types.DebuggerCallRestrictions.applyAll(dynamic, "independent compiler guard",
            () -> false, message -> { });
        blocked = Arm32CallPolicy.apply(elf, blocked, () -> false, message -> { });
        require(blocked.functions().getFirst().debuggerCallsDisabled() &&
            blocked.functionDeclarations().getFirst().debuggerCallsDisabled() &&
            blocked.functions().getFirst().effectiveCallingConvention().equals("__stdcall") &&
            blocked.functionDeclarations().getFirst().effectiveCallingConvention().equals("__stdcall"),
            "effective model erased independent restrictions");
    }

    private static void aggregateReturns(ElfImage elf) throws Exception {
        var integer = new TypeRef("integer");
        var aggregate = new TypeRef("aggregate");
        var pointer = new TypeRef("return_pointer");
        for (int count : new int[] {2, 3}) {
            for (int width : new int[] {4, 8}) {
                for (boolean mismatch : new boolean[] {false, true}) {
                    var members = new ArrayList<Member>();
                    for (int index = 0; index < count; index++) members.add(new Member("field" + index, integer, index * width));
                    var parameters = List.of(new Parameter("__return_storage_ptr__", pointer, true, true),
                        new Parameter("value", integer, false));
                    var nodes = List.<TypeNode>of(new BaseType("integer", "integer", width, BaseEncoding.SIGNED),
                        new AggregateType("aggregate", "aggregate", count * width, AggregateKind.STRUCTURE, members),
                        new IndirectionType("return_pointer", "aggregate *", 4, IndirectionKind.POINTER,
                            mismatch ? integer : aggregate),
                        new SubroutineType("callback", "callback", 0, aggregate, parameters, false, "__stdcall", "", false));
                    var input = new ProgramTypeModel(new TypeGraph(nodes), List.of(new FunctionSignature("returned", 0x1000,
                        aggregate, parameters, List.of(), false, false, "__stdcall", "USER_DEFINED", false, "")), List.of(),
                        new ghidradwarfforge.locations.VariableStorageModel(List.of()), List.of(),
                        List.of(new FunctionDeclaration("external", "declared", aggregate, parameters, false, false,
                            "__stdcall", "USER_DEFINED", false, "")));
                    var output = Arm32CallPolicy.apply(elf, input, () -> false, message -> { });
                    require(output.functions().getFirst().debuggerCallsDisabled() == mismatch &&
                        output.functionDeclarations().getFirst().debuggerCallsDisabled() == mismatch &&
                        ((SubroutineType) output.types().byKey().get("callback")).debuggerCallsDisabled() == mismatch,
                        "aggregate result carrier classification disagrees");
                }
            }
        }
    }

    private static void classified(ElfImage elf, String type, String convention, boolean variadic,
            String existing, boolean unmapped, boolean blocked) throws Exception {
        var input = model(type, convention, variadic, existing, unmapped);
        var diagnostics = new ArrayList<String>();
        var output = Arm32CallPolicy.apply(elf, input, () -> false, diagnostics::add);
        var function = output.functions().getFirst();
        var declaration = output.functionDeclarations().getFirst();
        var callback = (SubroutineType) output.types().byKey().get("callback");
        String label = type + "/" + convention + "/" + existing + "/" + variadic;
        require(function.debuggerCallsDisabled() == blocked && declaration.debuggerCallsDisabled() == blocked &&
            callback.debuggerCallsDisabled() == blocked, "callable forms disagree: " + label);
        require(function.callingConvention().equals(convention) && declaration.callingConvention().equals(convention) &&
            callback.callingConvention().equals(convention), "recorded convention lost: " + label);
        require(function.debuggerCallRestriction().contains(existing) &&
            declaration.debuggerCallRestriction().contains(existing) && callback.debuggerCallRestriction().contains(existing),
            "independent restriction erased: " + label);
        require(input.equals(model(type, convention, variadic, existing, unmapped)), "input mutated");
        require(output.globals().equals(input.globals()) && output.variableStorage().equals(input.variableStorage()) &&
            output.functionStatics().equals(input.functionStatics()) && output.lexicalScopes().equals(input.lexicalScopes()) &&
            output.classScopes().equals(input.classScopes()) && output.functionRelations().equals(input.functionRelations()),
            "unrelated recovered knowledge changed");
        require(output.equals(Arm32CallPolicy.apply(elf, output, () -> false, message -> { })), "policy is not idempotent");
    }

    private static ProgramTypeModel model(String selected, String convention, boolean variadic,
            String existing, boolean unmapped) {
        var ref = new TypeRef(selected);
        var nodes = new ArrayList<TypeNode>(List.of(
            new BaseType("integer", "int", 4, BaseEncoding.SIGNED),
            new BaseType("wide", "long long", 8, BaseEncoding.SIGNED),
            new BaseType("float", "float", 4, BaseEncoding.FLOAT),
            new BaseType("double", "double", 8, BaseEncoding.FLOAT),
            new BaseType("half", "half", 2, BaseEncoding.FLOAT),
            new TypedefType("alias", "real", 4, new TypeRef("float")),
            new TypedefType("bad_alias", "wrong real size", 8, new TypeRef("float")),
            new QualifiedType("qualified", "const real", 4, List.of(Qualifier.CONST), new TypeRef("alias")),
            new TypedefType("cycle", "cycle", 4, new TypeRef("cycle")),
            new IndirectionType("pointer", "real_ptr", 4, IndirectionKind.POINTER, new TypeRef("float")),
            new IndirectionType("wide_pointer", "wide_ptr", 8, IndirectionKind.POINTER, new TypeRef("float")),
            new ArrayType("array", "float[2]", 8, new TypeRef("float"), 2),
            new OpaqueType("opaque", "opaque", 4, "test incomplete type")));
        var parameters = List.of(new Parameter("value", ref, false));
        nodes.add(new SubroutineType("callback", "callback", 0, ref, parameters, variadic, convention, existing, unmapped));
        var previous = CompilerCallPolicySmoke.fixtureModel();
        var model = new ProgramTypeModel(new TypeGraph(nodes),
            List.of(new FunctionSignature("function0", 0x1000, ref, parameters, List.of(), variadic,
                false, convention, "USER_DEFINED", unmapped, existing), previous.functions().get(1)),
            previous.globals(), previous.variableStorage(),
            previous.functionStatics(), List.of(new FunctionDeclaration("external", "library::function", ref,
                parameters, variadic, false, convention, "USER_DEFINED", unmapped, existing)));
        return ghidradwarfforge.types.FunctionRelationsSmoke.withRelations(
            ghidradwarfforge.types.ClassScopeModelSmoke.withOwnership(model));
    }

    private static byte[] attributes(ByteOrder order, int... payload) {
        var out = ByteBuffer.allocate(16 + payload.length).order(order);
        out.put((byte) 'A').putInt(15 + payload.length).put("aeabi\0".getBytes(StandardCharsets.US_ASCII));
        out.put((byte) 1).putInt(5 + payload.length);
        for (int value : payload) out.put((byte) value);
        return out.array();
    }

    private static ElfImage write(Path path, ByteOrder order, int flags, byte[] attributes) throws Exception {
        byte[] strings = "\0.shstrtab\0.ARM.attributes\0".getBytes(StandardCharsets.US_ASCII);
        int size = attributes == null ? 0 : attributes.length;
        int table = (52 + size + strings.length + 3) & ~3;
        var out = ByteBuffer.allocate(attributes == null ? 52 : table + 120).order(order);
        out.put(new byte[] {0x7f, 'E', 'L', 'F', 1, (byte) (order == ByteOrder.LITTLE_ENDIAN ? 1 : 2), 1});
        out.putShort(16, (short) 2).putShort(18, (short) 40).putInt(20, 1);
        out.putInt(36, flags).putShort(40, (short) 52);
        if (attributes != null) {
            out.putInt(32, table).putShort(46, (short) 40).putShort(48, (short) 3).putShort(50, (short) 1);
            out.position(52); out.put(attributes).put(strings);
            out.putInt(table + 40, 1).putInt(table + 44, 3).putInt(table + 56, 52 + size);
            out.putInt(table + 60, strings.length).putInt(table + 72, 1);
            out.putInt(table + 80, 11).putInt(table + 84, 0x70000003).putInt(table + 96, 52);
            out.putInt(table + 100, size).putInt(table + 112, 1);
        }
        Files.write(path, out.array());
        var image = ElfImage.read(path);
        Arm32CallAbi.observe(image, () -> false);
        require(Arrays.equals(out.array(), Files.readAllBytes(path)), "input bytes modified");
        return image;
    }

    private static void rejected(Path path, ByteOrder order, int flags, byte[] attributes, String reason) throws Exception {
        var elf = write(path, order, flags, attributes);
        var observed = Arm32CallAbi.observe(elf, () -> false);
        require(!observed.valid() && observed.restriction().contains(reason), "missing rejection: " + reason);
        classified(elf, "integer", "__stdcall", false, "", false, true);
    }

    private static void require(boolean value, String message) {
        if (!value) throw new AssertionError(message);
        checks++;
    }
}
