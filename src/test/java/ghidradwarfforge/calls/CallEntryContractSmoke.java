package ghidradwarfforge.calls;

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidra.util.exception.CancelledException;
import ghidradwarfforge.elf.ElfImage;

/** Ordinary outgoing calls must not seed entry values at a split-frame label. */
public final class CallEntryContractSmoke {
    private static int checks;
    private static void require(boolean yes, String why) { if (!yes) throw new AssertionError(why); checks++; }
    private static String word(int value) {
        return HexFormat.of().formatHex(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value).array());
    }
    private static String transfer(boolean arm, boolean call, int from, int to) {
        return arm ? word((call ? 0x94000000 : 0x14000000) | (((to - from) >> 2) & 0x03ffffff)) :
            (call ? "e8" : "e9") + word(to - from - 5);
    }
    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])), new HeadlessGhidraApplicationConfiguration());
        Path output = Path.of(args[1]); Files.createDirectories(output);
        for (boolean arm : List.of(false, true)) {
            for (String mode : List.of("ordinary", "clean-tail", "dirty-tail", "annotated", "unselected", "interior", "patched-call", "fallthrough")) {
                check(arm, mode, output);
            }
        }
        System.out.println("call-entry-contract=PASS cases=16 checks=" + checks);
    }
    private static void check(boolean arm, String mode, Path output) throws Exception {
        String prefix = arm ? "fd7bbfa9" : "4883ec08";
        String returnCode = arm ? "c0035fd6" : "c3";
        String falling = mode.equals("fallthrough") ? (arm ? "1f2003d5" : "90") : "";
        int entryOffset = falling.length() / 2;
        byte[] caller = HexFormat.of().parseHex(falling + prefix + transfer(arm, true, 0x1004 + entryOffset, 0x2010) +
            (arm ? "fd7bc1a8" : "4883c408") + returnCode);
        String dirty = List.of("dirty-tail", "annotated").contains(mode) ? (arm ? "f37bbfa9" : "53") : "";
        int incomingAddress = 0x2000 + dirty.length() / 2;
        boolean ordinary = mode.equals("ordinary") || mode.equals("fallthrough");
        byte[] predecessor = HexFormat.of().parseHex(dirty + transfer(arm, ordinary, incomingAddress,
            mode.equals("interior") ? 0x1004 : 0x1000 + entryOffset) + (ordinary ? returnCode : ""));
        byte[] second = new byte[16 + returnCode.length() / 2];
        System.arraycopy(predecessor, 0, second, 0, predecessor.length);
        System.arraycopy(HexFormat.of().parseHex(returnCode), 0, second, 16, returnCode.length() / 2);
        byte[] original = GhidraTailStateProofSmoke.elf(arm, caller, second);
        Path path = output.resolve((arm ? "arm-" : "x86-") + mode + ".elf"); Files.write(path, original);
        var image = ElfImage.read(path);
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(arm ? "AARCH64:LE:64:v8A" : "x86:LE:64:default"));
        Object owner = new Object();
        var program = new ProgramDB("ordinary-entry", language,
            language.getCompilerSpecByID(new CompilerSpecID(arm ? "default" : "gcc")), owner);
        try {
            int tx = program.startTransaction("entry controls");
            try {
                var start = language.getDefaultSpace().getAddress(0x1000);
                var entry = start.add(entryOffset);
                var incoming = language.getDefaultSpace().getAddress(0x2000);
                var leaf = language.getDefaultSpace().getAddress(0x2010);
                program.getMemory().createInitializedBlock("caller", start, caller.length, (byte) 0, TaskMonitor.DUMMY, false).setExecute(true);
                program.getMemory().setBytes(start, caller);
                program.getMemory().createInitializedBlock("incoming", incoming, second.length, (byte) 0, TaskMonitor.DUMMY, false).setExecute(true);
                program.getMemory().setBytes(incoming, second);
                if (mode.equals("patched-call")) {
                    program.getMemory().setBytes(incoming, HexFormat.of().parseHex(transfer(arm, true, 0x2000, 0x1000)));
                }
                var body = new AddressSet(entry, start.add(caller.length - 1));
                var predecessorBody = new AddressSet(incoming, incoming.add(predecessor.length - 1));
                require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY), "caller decode");
                require(new DisassembleCommand(incoming, predecessorBody, true).applyTo(program, TaskMonitor.DUMMY), "incoming decode");
                var leafBody = new AddressSet(leaf, leaf.add(returnCode.length() / 2 - 1));
                require(new DisassembleCommand(leaf, leafBody, true).applyTo(program, TaskMonitor.DUMMY), "leaf decode");
                var function = program.getFunctionManager().createFunction("ordinary_caller", entry, body, SourceType.USER_DEFINED);
                if (entryOffset != 0) {
                    var fallingBody = new AddressSet(start, entry.previous());
                    require(new DisassembleCommand(start, fallingBody, true).applyTo(program, TaskMonitor.DUMMY), "fallthrough decode");
                    program.getFunctionManager().createFunction("falling_predecessor", start, fallingBody, SourceType.USER_DEFINED);
                }
                var predecessorFunction = program.getFunctionManager().createFunction("predecessor", incoming, predecessorBody, SourceType.USER_DEFINED);
                program.getFunctionManager().createFunction("leaf", leaf, leafBody, SourceType.USER_DEFINED);
                if (mode.equals("annotated")) program.getListing().getInstructionAt(incoming.add(dirty.length() / 2)).setFlowOverride(FlowOverride.CALL_RETURN);
                var selected = List.of("clean-tail", "dirty-tail", "annotated").contains(mode) ? List.of(function, predecessorFunction) : List.of(function);
                var proof = GhidraTailStateProof.verify(program, selected, image, 0, TaskMonitor.DUMMY);
                var values = GhidraCallArgumentFlow.analyze(program, proof, image, 0, TaskMonitor.DUMMY);
                boolean accepted = List.of("ordinary", "clean-tail").contains(mode);
                require(values.transfers().containsKey(entry.add(4)) == accepted,
                    (arm ? "arm/" : "x86/") + mode + " seeded an invalid entry state: " + values);
                require(proof.omissions().containsKey(entry) != accepted, "entry omission not recorded: " + mode);
                if (mode.equals("fallthrough")) require(proof.omissions().get(entry).contains("external fallthrough"), "missed actual fallthrough entry");
                if (mode.equals("patched-call")) require(proof.omissions().get(entry).contains("differs from original ELF"), "missed original-byte disagreement");
                if (mode.equals("ordinary")) {
                    int[] polls = {0};
                    GhidraTailStateProof.verify(program, selected, image, 0,
                        new TaskMonitorAdapter(true) { @Override public void checkCancelled() { polls[0]++; } });
                    for (int index = 1; index <= polls[0]; index++) {
                        final int stop = index; int[] count = {0};
                        try {
                            GhidraTailStateProof.verify(program, selected, image, 0,
                                new TaskMonitorAdapter(true) { @Override public void checkCancelled() throws CancelledException {
                                    if (++count[0] == stop) throw new CancelledException();
                                } });
                            throw new AssertionError("missed incoming-call cancellation " + stop);
                        }
                        catch (CancelledException expected) { checks++; }
                    }
                }
                require(Arrays.equals(original, Files.readAllBytes(path)), "changed original ELF");
            }
            finally { program.endTransaction(tx, false); }
        }
        finally { program.release(owner); }
    }
}
