package ghidradwarfforge.nativeapi;

import static ghidradwarfforge.nativeapi.DwarfConstants.DW_DLC_POINTER32;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_DLC_POINTER64;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_DLC_TARGET_BIGENDIAN;
import static ghidradwarfforge.nativeapi.DwarfConstants.DW_DLC_TARGET_LITTLEENDIAN;

import java.nio.ByteOrder;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.util.List;
import java.util.Set;
import java.util.ArrayList;
import java.util.Arrays;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.elf.ElfFunctionAlias;
import ghidradwarfforge.elf.ElfFunctionModeCue;
import ghidradwarfforge.calls.CallSitePlan;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.TypeGraph;

/** Checks the isolated, fail-closed ELF-to-libdwarf target description table. */
public final class DwarfTargetSmoke {
    private DwarfTargetSmoke() {
    }

    public static void main(String[] arguments) throws Exception {
        assertTarget(3, 4, ByteOrder.LITTLE_ENDIAN, "x86", "x86", true);
        assertTarget(62, 8, ByteOrder.LITTLE_ENDIAN, "x86_64", "x86_64", true);
        assertTarget(183, 8, ByteOrder.LITTLE_ENDIAN, "aarch64", "arm64", true);
        assertTarget(40, 4, ByteOrder.LITTLE_ENDIAN, "arm", "arm", true);
        assertTarget(8, 4, ByteOrder.LITTLE_ENDIAN, "mipsel", "mips", true);
        assertTarget(8, 4, ByteOrder.BIG_ENDIAN, "mips", "mips", false);

        expectFailure(() -> DwarfTarget.fromMetadata(3, 8,
            ByteOrder.LITTLE_ENDIAN), "requires ELF32");
        expectFailure(() -> DwarfTarget.fromMetadata(3, 4,
            ByteOrder.BIG_ENDIAN), "big-endian producer mode has not been audited");
        expectFailure(() -> DwarfTarget.fromMetadata(0xffff, 8,
            ByteOrder.LITTLE_ENDIAN), "unsupported ELF machine");
        expectFailure(() -> DwarfTarget.fromMetadata(62, 4,
            ByteOrder.LITTLE_ENDIAN), "requires ELF64");
        assertTarget(8, 8, ByteOrder.BIG_ENDIAN, "mips64", "mips", false);
        assertTarget(8, 8, ByteOrder.LITTLE_ENDIAN, "mips64el", "mips", true);
        expectFailure(() -> DwarfTarget.fromMetadata(8, 16,
            ByteOrder.BIG_ENDIAN), "requires ELF32");
        expectFailure(() -> DwarfTarget.fromMetadata(62, 8,
            ByteOrder.BIG_ENDIAN), "big-endian producer mode has not been audited");
        expectFailure(() -> DwarfTarget.fromMetadata(183, 4,
            ByteOrder.LITTLE_ENDIAN), "requires ELF64");
        expectFailure(() -> DwarfTarget.fromMetadata(183, 8,
            ByteOrder.BIG_ENDIAN), "big-endian producer mode has not been audited");
        assertTarget(40, 4, ByteOrder.BIG_ENDIAN, "arm", "arm", false);
        expectFailure(() -> DwarfTarget.fromMetadata(8, 4, null),
            "ELF byte order is required");
        descriptorAdmission();
        imageAgreement();
        System.out.println("dwarf-target-smoke=PASS");
    }

    private static void descriptorAdmission() throws Exception {
        for (String invalid : new String[] {null, "", " \t"}) {
            expectFailure(() -> new DwarfTarget(invalid, "x86_64", 8, true, "x86"), "invalid DWARF target");
            expectFailure(() -> new DwarfTarget("x86_64", invalid, 8, true, "x86"), "invalid DWARF target");
            expectFailure(() -> new DwarfTarget("x86_64", "x86_64", 8, true, invalid), "invalid DWARF target");
        }
        for (int width : new int[] {-1, 0, 1, 2, 16, Integer.MAX_VALUE}) {
            expectFailure(() -> new DwarfTarget("x86_64", "x86_64", width, true, "x86"), "invalid DWARF target");
        }
    }

    /** Header-only metadata fixture; no executable, native producer or architecture-support claim. */
    private static void imageAgreement() throws Exception {
        byte[] bytes = new byte[64];
        var header = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        header.put(new byte[] {0x7f, 'E', 'L', 'F', 2, 1, 1});
        header.putShort(16, (short) 2).putShort(18, (short) 62).putInt(20, 1).putShort(52, (short) 64);
        var path = Files.createTempFile("forge-target-agreement-", ".elf");
        try {
            Files.write(path, bytes);
            var image = ElfImage.read(path);
            var model = new ProgramTypeModel(new TypeGraph(List.of()), List.of(), List.of());
            var aliases = List.of(new ElfFunctionAlias("alias", "owner", 0x1000, 1, "0".repeat(64)));
            var cues = List.of(new ElfFunctionModeCue("owner", 0x1000, 1, 0x1000, "0".repeat(64)));
            for (var wrong : List.of(
                    new DwarfTarget("aarch64", "x86_64", 8, true, "x86"),
                    new DwarfTarget("x86_64", "arm64", 8, true, "x86"),
                    new DwarfTarget("x86_64", "x86_64", 4, true, "x86"),
                    new DwarfTarget("x86_64", "x86_64", 8, false, "x86"),
                    new DwarfTarget("x86_64", "x86_64", 8, true, "ARM"))) {
                var diagnostics = new ArrayList<String>();
                expectFailure(() -> wrong.requiredInstructionByteOrder(image), "instruction target disagrees with ELF");
                expectFailure(() -> wrong.elfAbiCallRestriction(image), "call ABI target disagrees with ELF");
                expectFailure(() -> wrong.applyCallRestrictions(image, model, () -> false, diagnostics::add),
                    "call ABI target disagrees with ELF");
                expectFailure(() -> wrong.planCallOriginSymbols(image, CallSitePlan.EMPTY, List.of(), model,
                    List.of(), Set.of(), () -> false, diagnostics::add), "call-origin target disagrees with ELF");
                expectFailure(() -> wrong.planFunctionAliases(image, aliases, List.of(), List.of(), () -> false,
                    diagnostics::add), "function-alias target disagrees with ELF");
                expectFailure(() -> wrong.planFunctionModeSymbols(image, cues, List.of(), () -> false,
                    diagnostics::add), "function-mode target disagrees with ELF");
                if (!diagnostics.isEmpty()) throw new AssertionError("mismatched target reached a downstream planner");
            }
            var correct = DwarfTarget.fromElf(image);
            if (correct.requiredInstructionByteOrder(image) != null || !correct.elfAbiCallRestriction(image).isEmpty() ||
                    !model.equals(correct.applyCallRestrictions(image, model, () -> false, ignored -> { })) ||
                    !correct.planCallOriginSymbols(image, CallSitePlan.EMPTY, List.of(), model, List.of(), Set.of(),
                        () -> false, ignored -> { }).isEmpty()) {
                throw new AssertionError("matching target metadata was rejected or altered");
            }
            var omitted = new ArrayList<String>();
            if (!correct.planFunctionModeSymbols(image, cues, List.of(), () -> false, omitted::add).isEmpty() ||
                    omitted.size() != 1 || !omitted.getFirst().contains("no audited mode-symbol planner")) {
                throw new AssertionError("ordinary x86 target invented ARM mode symbols");
            }
            if (!Arrays.equals(bytes, Files.readAllBytes(path))) throw new AssertionError("target admission changed the ELF");
        }
        finally { Files.delete(path); }
    }

    private static void assertTarget(int machine, int addressBytes, ByteOrder byteOrder,
            String name, String producerIsa, boolean littleEndian) {
        DwarfTarget target = DwarfTarget.fromMetadata(machine, addressBytes, byteOrder);
        if (!target.name().equals(name) || !target.producerIsa().equals(producerIsa) ||
                target.addressBytes() != addressBytes ||
                target.littleEndian() != littleEndian) {
            throw new AssertionError("unexpected target description " + target);
        }
        long expectedPointer = addressBytes == 8 ? DW_DLC_POINTER64 : DW_DLC_POINTER32;
        long expectedByteOrder = littleEndian
            ? DW_DLC_TARGET_LITTLEENDIAN : DW_DLC_TARGET_BIGENDIAN;
        if ((target.producerFlags() & expectedPointer) == 0 ||
                (target.producerFlags() & expectedByteOrder) == 0) {
            throw new AssertionError("target flags do not match " + target);
        }
    }

    @FunctionalInterface private interface Checked { void run() throws Exception; }

    private static void expectFailure(Checked action, String expectedMessage) throws Exception {
        try {
            action.run();
            throw new AssertionError("invalid target description was accepted");
        }
        catch (IllegalArgumentException expected) {
            if (!expected.getMessage().contains(expectedMessage)) {
                throw new AssertionError("unexpected failure: " + expected.getMessage());
            }
        }
    }
}
