package ghidradwarfforge;

import java.io.File;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.List;
import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.elf.CortexM3ProfileSmoke;
import ghidradwarfforge.elf.ElfImage;

/** Actual Ghidra language, context, functions and instructions; no mocked mode evidence. */
public final class GhidraCortexM3ProfileSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        Path input = Files.createTempFile("forge-cortex-ghidra-", ".elf");
        byte[] attributes = HexFormat.of().parseHex(
            "412e000000616561626900012400000005436f727465782d4d3300060a074d0902120414011501170318011a012201");
        try {
            Files.write(input, CortexM3ProfileSmoke.image(attributes, 0x05000200));
            var elf = ElfImage.read(input);
            for (String language : List.of("ARM:LE:32:v7", "ARM:LE:32:Cortex")) {
                var lang = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(language));
                Object owner = new Object();
                var program = new ProgramDB("cortex-profile", lang, lang.getDefaultCompilerSpec(), owner);
                try {
                    int tx = program.startTransaction("test-only profile contexts");
                    try {
                        var base = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x100);
                        program.getMemory().createInitializedBlock("flash", base, 32, (byte) 0, TaskMonitor.DUMMY, false);
                        var mode = program.getRegister("TMode");
                        program.getProgramContext().setValue(mode, base, base.add(31), BigInteger.ONE);
                        // BX LR in Thumb state. The second instruction is outside any function.
                        program.getMemory().setBytes(base, new byte[] {0x70, 0x47, 0x70, 0x47});
                        if (!new DisassembleCommand(base, new AddressSet(base, base.add(3)), false)
                                .applyTo(program)) throw new AssertionError("fixture failed to decode");
                        if (!new DisassembleCommand(base.add(2), new AddressSet(base.add(2), base.add(3)), false)
                                .applyTo(program)) throw new AssertionError("outside-function instruction missing");
                        program.getFunctionManager().createFunction("handler", base,
                            new AddressSet(base, base.add(1)), SourceType.USER_DEFINED);
                        if (!language.endsWith(":Cortex")) {
                            rejected(program, elf, "ARM:LE:32:Cortex/default");
                            continue;
                        }
                        GhidraCortexM3Profile.requireAgreement(program, elf, TaskMonitor.DUMMY);
                        checks++;
                        // Clear the instruction first: Ghidra forbids changing context under decoded code.
                        program.getListing().clearCodeUnits(base.add(2), base.add(5), false);
                        program.getProgramContext().setValue(mode, base.add(2), base.add(5), BigInteger.ZERO);
                        program.getMemory().setBytes(base.add(2), new byte[] {0x1e, (byte) 0xff, 0x2f, (byte) 0xe1});
                        if (!new DisassembleCommand(base.add(2), new AddressSet(base.add(2), base.add(5)), false)
                                .applyTo(program)) throw new AssertionError("ARM-state control failed to decode");
                        rejected(program, elf, "known Thumb context");
                        program.getListing().clearCodeUnits(base.add(2), base.add(5), false);
                        program.getListing().clearCodeUnits(base, base.add(1), false);
                        program.getProgramContext().setValue(mode, base, base.add(1), BigInteger.ZERO);
                        rejected(program, elf, "known Thumb context");
                    }
                    finally { program.endTransaction(tx, false); }
                }
                finally { program.release(owner); }
            }
        }
        finally { Files.delete(input); }
        System.out.println("ghidra-cortex-m3-profile=PASS checks=" + checks);
    }

    private static void rejected(ProgramDB program, ElfImage image, String reason) throws Exception {
        try {
            GhidraCortexM3Profile.requireAgreement(program, image, TaskMonitor.DUMMY);
            throw new AssertionError("contradictory Ghidra context accepted");
        }
        catch (IllegalArgumentException expected) {
            if (!expected.getMessage().contains(reason)) throw new AssertionError(expected);
            checks++;
        }
    }
}
