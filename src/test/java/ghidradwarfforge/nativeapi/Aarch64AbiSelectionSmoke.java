package ghidradwarfforge.nativeapi;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

import ghidradwarfforge.CompilerCallPolicySmoke;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.types.ProgramTypeModel.FunctionDeclaration;
import ghidradwarfforge.types.ProgramTypeModel.FunctionSignature;
import ghidradwarfforge.types.TypeGraph.SubroutineType;

/** Real ELF metadata, all callable DIE forms and untouched analyst knowledge. */
public final class Aarch64AbiSelectionSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        var path = Files.createTempFile("forge-abi-selection-", ".elf");
        var input = CompilerCallPolicySmoke.fixtureModel();
        try {
            for (int type : List.of(2, 3)) {
                for (int osAbi : List.of(0, 3, 9, 255)) {
                    for (int version : List.of(0, 1)) {
                        for (int flags : List.of(0, 1, Integer.MIN_VALUE)) {
                            byte[] bytes = header(type, osAbi, version, flags);
                            Files.write(path, bytes);
                            var image = ElfImage.read(path);
                            var target = DwarfTarget.fromElf(image);
                            boolean restricted = !(osAbi == 0 || osAbi == 3) || version != 0 || flags != 0;
                            String reason = target.elfAbiCallRestriction(image);
                            require(reason.isEmpty() != restricted, "wrong metadata selection");
                            var diagnostics = new ArrayList<String>();
                            var output = target.applyCallRestrictions(image, input, () -> false, diagnostics::add);
                            for (int index = 0; index < 2; index++) {
                                var before = input.functions().get(index);
                                var after = output.functions().get(index);
                                require(after.debuggerCallsDisabled() == (restricted || index == 1), "function call bypass");
                                require(before.equals(new FunctionSignature(after.name(), after.address(), after.returnType(),
                                    after.parameters(), after.locals(), after.variadic(), after.noReturn(), after.callingConvention(),
                                    after.signatureSource(), after.nonDefaultCallingConvention(), before.debuggerCallRestriction(),
                                    after.effectiveCallingConvention())),
                                    "curated function knowledge changed");
                                var oldDeclaration = input.functionDeclarations().get(index);
                                var declaration = output.functionDeclarations().get(index);
                                require(declaration.debuggerCallsDisabled() == (restricted || index == 1), "declaration bypass");
                                require(oldDeclaration.equals(new FunctionDeclaration(declaration.key(), declaration.name(),
                                    declaration.returnType(), declaration.parameters(), declaration.variadic(), declaration.noReturn(),
                                    declaration.callingConvention(), declaration.signatureSource(), declaration.nonDefaultCallingConvention(),
                                    oldDeclaration.debuggerCallRestriction(), declaration.effectiveCallingConvention())),
                                    "external declaration changed");
                                var oldType = (SubroutineType) input.types().byKey().get("callback" + index);
                                var newType = (SubroutineType) output.types().byKey().get(oldType.key());
                                require(newType.debuggerCallsDisabled() == (restricted || index == 1), "callback bypass");
                                require(oldType.equals(new SubroutineType(newType.key(), newType.name(), newType.byteSize(),
                                    newType.returnType(), newType.parameters(), newType.variadic(), newType.callingConvention(),
                                    oldType.debuggerCallRestriction())), "callback type changed");
                                require(after.debuggerCallRestriction().startsWith(before.debuggerCallRestriction()), "prior restriction lost");
                            }
                            require(output.globals().equals(input.globals()) && output.variableStorage() == input.variableStorage() &&
                                output.functionStatics().equals(input.functionStatics()) && output.classScopes() == input.classScopes() &&
                                output.lexicalScopes().equals(input.lexicalScopes()) && output.functionRelations() == input.functionRelations(),
                                "locations or ownership changed");
                            require(output.types().nodes().stream().filter(n -> !(n instanceof SubroutineType)).toList().equals(
                                input.types().nodes().stream().filter(n -> !(n instanceof SubroutineType)).toList()), "data types changed");
                            require(diagnostics.size() == (restricted ? 6 : 0), "missing profile diagnostics");
                            require(output.equals(target.applyCallRestrictions(image, output, () -> false, ignored -> { })),
                                "restriction not idempotent");
                            require(Arrays.equals(bytes, Files.readAllBytes(path)), "input ELF changed");
                            if (!restricted) require(output == input, "baseline metadata altered model");
                            AtomicInteger total = new AtomicInteger();
                            target.applyCallRestrictions(image, input, () -> { total.incrementAndGet(); return false; }, ignored -> { });
                            for (int limit : List.of(1, Math.max(1, total.get() / 2), total.get())) {
                                AtomicInteger count = new AtomicInteger();
                                try {
                                    target.applyCallRestrictions(image, input, () -> count.incrementAndGet() >= limit, ignored -> { });
                                    throw new AssertionError("cancellation ignored");
                                }
                                catch (CancellationException expected) { checks++; }
                            }
                        }
                    }
                }
            }
            require(input.equals(CompilerCallPolicySmoke.fixtureModel()), "input model mutated");
        }
        finally { Files.deleteIfExists(path); }
        System.out.println("aarch64-abi-selection-smoke=PASS checks=" + checks);
    }

    private static byte[] header(int type, int osAbi, int version, int flags) {
        var buffer = ByteBuffer.allocate(64).order(ByteOrder.LITTLE_ENDIAN);
        buffer.put(new byte[] { 0x7f, 'E', 'L', 'F', 2, 1, 1, (byte) osAbi, (byte) version });
        buffer.putShort(16, (short) type);
        buffer.putShort(18, (short) 183);
        buffer.putInt(20, 1);
        buffer.putInt(48, flags);
        buffer.putShort(52, (short) 64);
        buffer.putShort(54, (short) 56);
        buffer.putShort(58, (short) 64);
        return buffer.array();
    }

    private static void require(boolean value, String message) {
        checks++;
        if (!value) throw new AssertionError(message);
    }
}
