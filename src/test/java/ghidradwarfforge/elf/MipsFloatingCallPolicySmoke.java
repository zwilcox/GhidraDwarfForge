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
public final class MipsFloatingCallPolicySmoke {
    private static int checks;
    private record Case(String type, boolean parameter, boolean variadic, String existing) { }
    private static final List<Case> CASES = List.of(
        new Case("i", false, false, ""), new Case("p", true, false, ""),
        new Case("f", true, false, ""), new Case("d", false, false, ""),
        new Case("q", true, false, "prior custom restriction"),
        new Case("wide", false, false, ""), new Case("i", true, true, ""),
        new Case("cycle1", false, false, ""));

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("forge-mips-call-");
        var model = ghidradwarfforge.types.FunctionRelationsSmoke.withRelations(ghidradwarfforge.types.ClassScopeModelSmoke.withOwnership(model()));
        for (ByteOrder order : List.of(ByteOrder.BIG_ENDIAN, ByteOrder.LITTLE_ENDIAN)) {
            for (int abi : List.of(0, 1, 2, 3, 4, 5, 6, 7, 255)) {
                for (int carrier : List.of(0, 1, 2, 3)) {
                    Path path = root.resolve("input.elf");
                    var fixture = fixture(path, order, abi, carrier);
                    byte[] original = Files.readAllBytes(path);
                    var image = ElfImage.read(path);
                    var diagnostics = new ArrayList<String>();
                    var output = MipsFloatingCallPolicy.apply(image, model, () -> false, diagnostics::add);
                    boolean fp32 = abi == 1 && carrier != 0;
                    int blocked = 0;
                    for (int index = 0; index < CASES.size(); index++) {
                        var selected = CASES.get(index);
                        boolean restriction = selected.type().equals("wide") || selected.type().equals("cycle1") ||
                            (!fp32 && (selected.variadic() || List.of("f", "d", "q").contains(selected.type())));
                        var before = model.functions().get(index);
                        var after = output.functions().get(index);
                        require(after.debuggerCallsDisabled() == (restriction || !selected.existing().isEmpty()),
                            "incorrect floating call decision");
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
                    require(output.classScopes() == model.classScopes(), "class ownership dropped by call policy");
                    require(output.functionRelations() == model.functionRelations(), "function relationships dropped by call policy");
                    require(output.equals(MipsFloatingCallPolicy.apply(image, output, () -> false, ignored -> { })),
                        "restriction duplicated");
                    require(Arrays.equals(original, Files.readAllBytes(path)), "original changed");
                    AtomicInteger total = new AtomicInteger();
                    MipsFloatingCallPolicy.apply(image, model, () -> { total.incrementAndGet(); return false; }, ignored -> { });
                    for (int limit : List.of(1, total.get() / 2, total.get())) {
                        AtomicInteger count = new AtomicInteger();
                        try {
                            MipsFloatingCallPolicy.apply(image, model, () -> count.incrementAndGet() >= limit, ignored -> { });
                            throw new AssertionError("ignored cancellation");
                        }
                        catch (CancellationException expected) {
                            checks++;
                        }
                    }
                    fixture.patch(18, 2, 40);
                    require(MipsFloatingCallPolicy.apply(ElfImage.read(path), model, () -> false,
                        ignored -> { }) == model, "unrelated target changed");
                }
            }
        }
        System.out.println("mips-floating-call-policy-smoke=PASS checks=" + checks);
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
            new BaseType("f", "float", 4, BaseEncoding.FLOAT), new BaseType("d", "double", 8, BaseEncoding.FLOAT),
            new BaseType("wide", "long double", 16, BaseEncoding.FLOAT), new TypedefType("alias", "alias", 8, new TypeRef("d")),
            new QualifiedType("q", "const alias", 8, List.of(Qualifier.CONST), new TypeRef("alias")),
            new IndirectionType("p", "double *", 4, IndirectionKind.POINTER, new TypeRef("d")),
            new TypedefType("cycle1", "cycle1", 8, new TypeRef("cycle2")),
            new TypedefType("cycle2", "cycle2", 8, new TypeRef("cycle1"))));
        var functions = new ArrayList<FunctionSignature>();
        var declarations = new ArrayList<FunctionDeclaration>();
        for (int index = 0; index < CASES.size(); index++) {
            var selected = CASES.get(index);
            var result = new TypeRef(selected.parameter() ? "v" : selected.type());
            var parameters = selected.parameter() ? List.of(new Parameter("argument", new TypeRef(selected.type()), false)) :
                List.<Parameter>of();
            functions.add(new FunctionSignature("function" + index, 0x1000 + index * 16, result, parameters,
                List.of(), selected.variadic(), false, "default", "USER_DEFINED", false, selected.existing()));
            declarations.add(new FunctionDeclaration("external:" + index, "external" + index, result, parameters,
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
