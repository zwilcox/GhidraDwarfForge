package ghidradwarfforge.calls;

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

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
import ghidradwarfforge.elf.ElfImage;

/** Explicit omission for two currently unproved AArch64 guard forms. */
public final class Aarch64SwitchOmissionSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        run(Path.of(args[1]));
    }

    static void run(Path directory) throws Exception {
        Files.createDirectories(directory);
        for (long delta : new long[] {0, 0x400000}) {
            for (int maximum : new int[] {0, 1, 254}) check(directory, delta, maximum, false);
            for (int maximum : new int[] {1, 255}) check(directory, delta, maximum, true);
        }
        System.out.println("aarch64-switch-omission=PASS checks=" + checks);
    }

    private static void check(Path directory, long delta, int maximum, boolean inclusive) throws Exception {
        var code = ByteBuffer.allocate(0x54).order(ByteOrder.LITTLE_ENDIAN);
        for (int i = 0; i < code.capacity(); i += 4) code.putInt(i, 0xd503201f); // NOP
        // Independently assembled with GNU as/ld at 0x1000:
        // CMP W0,#limit; B.HI (inclusive) or B.HS (strict) 0x1050; ADRP X1,0x2000;
        // MOV W0,W0; LDR X2,[X1,X0,LSL #3]; BR X2.
        int limit = inclusive ? maximum : maximum + 1;
        code.putInt(0, 0x7100001f | limit << 10).putInt(4, inclusive ? 0x54000268 : 0x54000262)
            .putInt(8, 0xb0000001).putInt(12, 0x2a0003e0)
            .putInt(16, 0xf8607822).putInt(20, 0xd61f0040);
        for (int offset : new int[] {0x30, 0x40, 0x50}) code.putInt(offset, 0xd65f03c0);
        var table = ByteBuffer.allocate((maximum + 1) * 8).order(ByteOrder.LITTLE_ENDIAN);
        for (int i = 0; i <= maximum; i++) table.putLong(i == 0 ? 0x1030 : 0x1040);
        byte[] original = GhidraTailStateProofSmoke.elf(true, code.array(), table.array());
        ByteBuffer.wrap(original).order(ByteOrder.LITTLE_ENDIAN).putInt(124, 4); // Read-only table LOAD.
        Path input = directory.resolve("aarch64-" + maximum + "-" + delta + "-" + inclusive + ".elf");
        Files.write(input, original);
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("AARCH64:LE:64:v8A"));
        Object owner = new Object();
        var program = new ProgramDB("aarch64-switch", language, language.getDefaultCompilerSpec(), owner);
        try {
            int tx = program.startTransaction("original-image switch fixture");
            try {
                var entry = language.getDefaultSpace().getAddress(0x1000 + delta);
                var data = language.getDefaultSpace().getAddress(0x2000 + delta);
                var body = new AddressSet(entry, entry.add(code.capacity() - 1));
                program.getMemory().createInitializedBlock("code", entry, code.capacity(), (byte) 0,
                    TaskMonitor.DUMMY, false).setExecute(true);
                program.getMemory().setBytes(entry, code.array());
                program.getMemory().createInitializedBlock("table", data, table.capacity(), (byte) 0,
                    TaskMonitor.DUMMY, false);
                program.getMemory().setBytes(data, table.array());
                require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY), "guard decode");
                for (int offset : new int[] {0x30, 0x40, 0x50}) {
                    require(new DisassembleCommand(entry.add(offset), body, true).applyTo(program, TaskMonitor.DUMMY), "case decode");
                }
                program.getFunctionManager().createFunction("dispatch", entry, body, SourceType.USER_DEFINED);
                var branch = program.getListing().getInstructionAt(entry.add(4));
                require(branch.getFlowType().isConditional() && branch.getFlowType().isJump() &&
                    branch.getDefaultFlows().length == 1 && branch.getDefaultFlows()[0].equals(entry.add(0x50)),
                    "fixture must decode a conditional branch to the out-of-range fallback");
                long modification = program.getModificationNumber();
                try {
                    GhidraBoundedSwitch.prove(program, program.getListing().getInstructionAt(entry),
                        ElfImage.read(input), delta, TaskMonitor.DUMMY);
                    throw new AssertionError("guard support changed; review target evidence before updating this limitation");
                }
                catch (IllegalArgumentException rejected) {
                    require(rejected.getMessage().equals("guard does not establish a bounded fallthrough"),
                        "unexpected guard refusal: " + rejected.getMessage());
                }
                require(program.getModificationNumber() == modification && Arrays.equals(original, Files.readAllBytes(input)),
                    "guard refusal modified the program or original ELF");
            }
            finally { program.endTransaction(tx, false); }
        }
        finally { program.release(owner); }
    }

    private static void require(boolean condition, String reason) {
        checks++;
        if (!condition) throw new AssertionError(reason);
    }
}
