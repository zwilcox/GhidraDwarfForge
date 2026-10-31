package ghidradwarfforge.elf;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

import ghidradwarfforge.locations.VariableStorageModel;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.ProgramTypeModel.FunctionDeclaration;
import ghidradwarfforge.types.ProgramTypeModel.FunctionSignature;
import ghidradwarfforge.types.TypeGraph;
import ghidradwarfforge.types.TypeGraph.*;

/** Target ABI bytes, signature preservation, aliases, declarations and cancellation. */
public final class MipsAggregateCallPolicySmoke {
    private static int checks;
    private record Case(String result, String argument, boolean variadic, String existing,
            boolean admissible) { }
    private static final List<Case> CASES = List.of(
        new Case("i", "wide", false, "", true),
        new Case("aggregate", "i", false, "", true),
        new Case("aggregate", "p", false, "", true),
        new Case("aggregate", "wide", false, "", false),
        new Case("qualified", "i", false, "prior custom restriction", true),
        new Case("union", "enum", false, "", true),
        new Case("aggregate", "cycle1", false, "", false),
        new Case("aggregate", "f", false, "", false),
        new Case("aggregate", "i", true, "", false),
        new Case("aggregate", "aggregate", false, "", false),
        new Case("aggregate", "char", false, "", true),
        new Case("aggregate", "ref", false, "", false),
        new Case("aggregate", "pointer64", false, "", false));

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("forge-mips-call-");
        var model = model();
        for (ByteOrder order : List.of(ByteOrder.BIG_ENDIAN, ByteOrder.LITTLE_ENDIAN)) {
            for (int abi : List.of(0, 1, 2, 3, 4, 5, 6, 7, 255)) {
                for (int carrier : List.of(0, 1, 2, 3)) {
                    Path path = root.resolve("input.elf");
                    var fixture = fixture(path, order, abi, carrier);
                    byte[] original = Files.readAllBytes(path);
                    var image = ElfImage.read(path);
                    var diagnostics = new ArrayList<String>();
                    var output = MipsAggregateCallPolicy.apply(image, model, () -> false, diagnostics::add);
                    boolean profile = (abi == 1 || abi == 5) && carrier != 0;
                    int blocked = 0;
                    for (int index = 0; index < CASES.size(); index++) {
                        var selected = CASES.get(index);
                        boolean restriction = !selected.result().equals("i") &&
                            (!profile || !selected.admissible());
                        var before = model.functions().get(index);
                        var after = output.functions().get(index);
                        require(after.debuggerCallsDisabled() == (restriction || !selected.existing().isEmpty()),
                            "incorrect aggregate call decision");
                        require(after.debuggerCallRestriction().startsWith(selected.existing()), "prior restriction lost");
                        require(before.equals(new FunctionSignature(after.name(), after.address(), after.returnType(),
                            after.parameters(), after.locals(), after.variadic(), after.noReturn(), after.callingConvention(),
                            after.signatureSource(), after.nonDefaultCallingConvention(), before.debuggerCallRestriction())),
                            "signature changed");
                        var declaration = output.functionDeclarations().get(index);
                        var oldDeclaration = model.functionDeclarations().get(index);
                        require(declaration.debuggerCallRestriction().equals(after.debuggerCallRestriction()),
                            "declaration policy diverged");
                        require(oldDeclaration.equals(new FunctionDeclaration(declaration.key(), declaration.name(),
                            declaration.returnType(), declaration.parameters(), declaration.variadic(), declaration.noReturn(),
                            declaration.callingConvention(), declaration.signatureSource(), declaration.nonDefaultCallingConvention(),
                            oldDeclaration.debuggerCallRestriction())), "declaration changed");
                        var oldType = (SubroutineType) model.types().byKey().get("subroutine" + index);
                        var newType = (SubroutineType) output.types().byKey().get(oldType.key());
                        require(newType.debuggerCallRestriction().equals(after.debuggerCallRestriction()),
                            "function-pointer restriction diverged");
                        require(oldType.equals(new SubroutineType(newType.key(), newType.name(), newType.byteSize(),
                            newType.returnType(), newType.parameters(), newType.variadic(), newType.callingConvention(),
                            oldType.debuggerCallRestriction())), "function-pointer signature changed");
                        if (restriction) blocked++;
                    }
                    require(diagnostics.size() == blocked * 3, "missing restriction diagnostics");
                    require(output.types().nodes().stream().filter(n -> !(n instanceof SubroutineType)).toList().equals(
                        model.types().nodes().stream().filter(n -> !(n instanceof SubroutineType)).toList()) &&
                        output.variableStorage() == model.variableStorage(), "non-function types or locations changed");
                    require(output.equals(MipsAggregateCallPolicy.apply(image, output, () -> false, ignored -> { })),
                        "restriction duplicated");
                    require(Arrays.equals(original, Files.readAllBytes(path)), "original changed");
                    AtomicInteger total = new AtomicInteger();
                    MipsAggregateCallPolicy.apply(image, model, () -> { total.incrementAndGet(); return false; }, ignored -> { });
                    for (int limit : List.of(1, total.get() / 2, total.get())) {
                        AtomicInteger count = new AtomicInteger();
                        try {
                            MipsAggregateCallPolicy.apply(image, model, () -> count.incrementAndGet() >= limit, ignored -> { });
                            throw new AssertionError("ignored cancellation");
                        }
                        catch (CancellationException expected) {
                            checks++;
                        }
                    }
                    fixture.patch(18, 2, 40);
                    require(MipsAggregateCallPolicy.apply(ElfImage.read(path), model, () -> false,
                        ignored -> { }) == model, "unrelated target changed");
                }
            }
        }
        System.out.println("mips-aggregate-call-policy-smoke=PASS checks=" + checks);
    }

    private static ElfBuildIdFixtures.Fixture fixture(Path path, ByteOrder order, int abi, int carrier) throws Exception {
        byte[] bytes = ByteBuffer.allocate(24).order(order).putShort((short) 0)
            .put(new byte[] { 32, 2, 1, 1, 0, (byte) abi }).putInt(0).putInt(0).putInt(1).putInt(0).array();
        var f = ElfBuildIdFixtures.create(path, false, order, bytes,
            (carrier & 1) != 0 ? List.of(new ElfBuildIdFixtures.View(0, 24, 8, 0x7000002a, 2)) : List.of(),
            (carrier & 2) != 0 ? List.of(new ElfBuildIdFixtures.View(0, 24, 8, 0x70000003, 4)) : List.of(),
            false, false, false, 0);
        f.patch(18, 2, 8);
        f.patch(36, 4, 0x70001007);
        return f;
    }

    private static ProgramTypeModel model() {
        var types = new TypeGraph(List.of(new VoidType("v"), new BaseType("i", "int", 4, BaseEncoding.SIGNED),
            new BaseType("f", "float", 4, BaseEncoding.FLOAT),
            new BaseType("wide", "long long", 8, BaseEncoding.SIGNED),
            new BaseType("char", "signed char", 1, BaseEncoding.SIGNED_CHAR),
            new AggregateType("aggregate", "triple", 24, AggregateKind.STRUCTURE,
                List.of(new Member("a", new TypeRef("wide"), 0), new Member("b", new TypeRef("wide"), 8),
                    new Member("c", new TypeRef("wide"), 16))),
            new AggregateType("union", "choice", 8, AggregateKind.UNION,
                List.of(new Member("a", new TypeRef("wide"), 0))),
            new TypedefType("alias", "alias", 24, new TypeRef("aggregate")),
            new QualifiedType("qualified", "const alias", 24, List.of(Qualifier.CONST), new TypeRef("alias")),
            new EnumType("enum", "enum", 4, true, List.of(new Enumerator("one", 1))),
            new IndirectionType("p", "int *", 4, IndirectionKind.POINTER, new TypeRef("i")),
            new IndirectionType("hidden", "triple *", 4, IndirectionKind.POINTER, new TypeRef("aggregate")),
            new IndirectionType("pointer64", "int *", 8, IndirectionKind.POINTER, new TypeRef("i")),
            new IndirectionType("ref", "int &", 4, IndirectionKind.LVALUE_REFERENCE, new TypeRef("i")),
            new TypedefType("cycle1", "cycle1", 8, new TypeRef("cycle2")),
            new TypedefType("cycle2", "cycle2", 8, new TypeRef("cycle1"))));
        var functions = new ArrayList<FunctionSignature>();
        var declarations = new ArrayList<FunctionDeclaration>();
        for (int index = 0; index < CASES.size(); index++) {
            var selected = CASES.get(index);
            var result = new TypeRef(selected.result());
            var parameters = new ArrayList<Parameter>();
            if (!selected.result().equals("i")) {
                parameters.add(new Parameter("hidden", new TypeRef("hidden"), true, true));
            }
            parameters.add(new Parameter("argument", new TypeRef(selected.argument()), false));
            functions.add(new FunctionSignature("function" + index, 0x1000 + index * 16, result, parameters,
                List.of(), selected.variadic(), false, "default", "USER_DEFINED", false, selected.existing()));
            declarations.add(new FunctionDeclaration("external:" + index, "external" + String.format("%02d", index), result, parameters,
                selected.variadic(), false, "default", "USER_DEFINED", false, selected.existing()));
        }
        var nodes = new ArrayList<TypeNode>(types.nodes());
        for (int index = 0; index < functions.size(); index++) {
            var function = functions.get(index);
            nodes.add(new SubroutineType("subroutine" + index, "callback" + index, 0, function.returnType(),
                function.parameters().stream().filter(p -> !p.returnStorage()).toList(), function.variadic(),
                function.callingConvention(), function.debuggerCallRestriction()));
        }
        return new ProgramTypeModel(new TypeGraph(nodes), functions, List.of(), new VariableStorageModel(List.of()), List.of(), declarations);
    }

    private static void require(boolean value, String message) {
        checks++;
        if (!value) throw new AssertionError(message);
    }
}
