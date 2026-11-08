package ghidradwarfforge;

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.nativeapi.DwarfTarget;

/** Real language descriptions distinguish BE8 instruction order from data order. */
public final class GhidraArmBe8ProfileSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        Path input = Files.createTempFile("forge-be8-profile-", ".elf");
        try {
            for (int flags : new int[] {0x05800000, 0x05800200, 0x05800400}) {
                byte[] original = image(false, flags);
                Files.write(input, original);
                var elf = ElfImage.read(input);
                var target = DwarfTarget.fromElf(elf);
                require(target.addressBytes() == 4 && !target.littleEndian(), "BE8 data representation");
                require(target.producerIsa().equals("arm"), "audited producer ISA");
                require(target.requiredInstructionByteOrder(elf) == ByteOrder.LITTLE_ENDIAN,
                    "BE8 instruction representation");
                var callModel = CompilerCallPolicySmoke.fixtureModel();
                var classified = target.applyCallRestrictions(elf, callModel, () -> false, message -> { });
                require(classified.functions().get(1).debuggerCallsDisabled() &&
                    classified.functions().get(1).debuggerCallRestriction().contains("existing custom restriction"),
                    "BE8 encoding must not erase independent signature restrictions");
                for (String language : List.of("ARM:LEBE:32:v7LEInstruction", "ARM:LEBE:32:v8LEInstruction")) {
                    agreement(elf, language, true);
                }
                for (String language : List.of("ARM:BE:32:v7", "ARM:BE:32:v8", "ARM:LE:32:v8")) {
                    agreement(elf, language, false);
                }
                require(Arrays.equals(original, Files.readAllBytes(input)), "original remains unchanged");
            }
            for (int flags : new int[] {0, 0x05000000, 0x05000400, 0x04800000, 0x00800000, 0x05c00400}) {
                Files.write(input, image(false, flags));
                try {
                    DwarfTarget.fromElf(ElfImage.read(input));
                    throw new AssertionError("unaudited ARM encoding accepted");
                }
                catch (IllegalArgumentException expected) {
                    require(expected.getMessage().contains("requires EABI5 BE8"), "specific encoding rejection");
                }
            }
            Files.write(input, image(true, 0x05800400));
            try {
                DwarfTarget.fromElf(ElfImage.read(input));
                throw new AssertionError("BE8 flag accepted with little-endian ELF data");
            }
            catch (IllegalArgumentException expected) {
                require(expected.getMessage().contains("contradicts little-endian"), "contradiction diagnostic");
            }
        }
        finally {
            Files.delete(input);
        }
        System.out.println("ghidra-arm-be8-profile=PASS checks=" + checks);
    }

    private static void agreement(ElfImage elf, String id, boolean accepted) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(id));
        Object owner = new Object();
        var program = new ProgramDB("be8-agreement", language, language.getDefaultCompilerSpec(), owner);
        try {
            GhidraTargetAgreement.requireAgreement(program, elf);
            require(accepted, "contradictory language accepted: " + id);
        }
        catch (IllegalStateException expected) {
            require(!accepted, "matching language rejected: " + id);
            require(expected.getMessage().contains("before extraction and native production"),
                "preflight failure boundary");
            require(expected.getMessage().contains("language=" + id), "diagnostic language identity");
            if (id.contains(":BE:")) {
                require(expected.getMessage().contains("instruction byte-order mismatch"),
                    "same data order must not hide instruction contradiction");
            }
        }
        finally {
            program.release(owner);
        }
    }

    private static byte[] image(boolean little, int flags) {
        ByteBuffer out = ByteBuffer.allocate(52).order(little ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);
        out.put(new byte[] {0x7f, 'E', 'L', 'F', 1, (byte) (little ? 1 : 2), 1});
        out.putShort(16, (short) 2).putShort(18, (short) 40).putInt(20, 1);
        out.putInt(36, flags).putShort(40, (short) 52);
        return out.array();
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }
}
