package ghidradwarfforge.unwind;

import java.io.File;
import java.math.BigInteger;
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
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.targets.UnwindAbiProfile;
import ghidradwarfforge.unwind.UnwindFlow.*;

/** Real compiler specs, native hidden-PAC controls and explicit ELF metadata. */
public final class UnwindAbiProfileSmoke {
    private static int checks;
    private static Path output;
    private static final StringBuilder evidence = new StringBuilder();

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        output = Path.of(args[1]);
        Files.createDirectories(output);
        for (boolean arm : List.of(false, true)) {
            for (String compiler : arm ? List.of("default", "windows", "golang") : List.of("gcc", "windows", "golang")) {
                run(arm, compiler, "ordinary", arm ? "f37bbfa9f37bc1a8c0035fd6" : "415490415cc3", null);
            }
        }
        run(true, "default", "pac-hidden", "3f2303d5c0035fd6", BigInteger.ZERO);
        run(true, "default", "pac-visible", "3f2303d5c0035fd6", BigInteger.ONE);
        run(true, "default", "pac-later", "1f2003d53f2303d5c0035fd6", BigInteger.ZERO);
        run(true, "default", "simd", "e80700fdc0035fd6", null);
        run(false, "gcc", "wrong-mode", "90c3", BigInteger.ZERO);
        Files.writeString(output.resolve("observations.txt"), evidence.toString());
        System.out.println("unwind-abi-profile-smoke=PASS checks=" + checks);
    }

    private static void require(boolean value, String reason) {
        if (!value) throw new AssertionError(reason);
        checks++;
    }
    @FunctionalInterface private interface Checked { void run() throws Exception; }
    private static void rejected(Checked action) throws Exception {
        try { action.run(); throw new AssertionError("unsupported unwind profile accepted"); }
        catch (IllegalArgumentException expected) { checks++; }
    }
    private static ElfImage image(String name, int machine, boolean wide, ByteOrder order, int type, int flags, int osAbi, long entry)
            throws Exception {
        var data = ByteBuffer.allocate(wide ? 64 : 52).order(order);
        data.put(new byte[] {0x7f, 'E', 'L', 'F', (byte) (wide ? 2 : 1),
            (byte) (order == ByteOrder.LITTLE_ENDIAN ? 1 : 2), 1, (byte) osAbi, 0});
        data.putShort(16, (short) type).putShort(18, (short) machine).putInt(20, 1);
        if (wide) data.putLong(24, entry).putInt(48, flags).putShort(52, (short) 64);
        else data.putInt(24, (int) entry).putInt(36, flags).putShort(40, (short) 52);
        Path path = output.resolve(name + ".elf");
        Files.write(path, data.array());
        return ElfImage.read(path);
    }

    private static void run(boolean arm, String compiler, String shape, String hex, BigInteger context) throws Exception {
        String id = arm ? "AARCH64:LE:64:v8A" : "x86:LE:64:default";
        String tag = (arm ? "aarch64" : "x86") + "-" + compiler + "-" + shape;
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(id));
        Object owner = new Object();
        var program = new ProgramDB(tag, language, language.getCompilerSpecByID(new CompilerSpecID(compiler)), owner);
        try {
            int transaction = program.startTransaction("unwind profile fixture");
            try {
                byte[] bytes = HexFormat.of().parseHex(hex);
                var entry = language.getDefaultSpace().getAddress(0x1000);
                var end = entry.add(bytes.length - 1);
                program.getMemory().createInitializedBlock("text", entry, bytes.length, (byte) 0, TaskMonitor.DUMMY, false).setExecute(true);
                program.getMemory().setBytes(entry, bytes);
                if (context != null) program.getProgramContext().setValue(program.getRegister(arm ? "ShowPAC" : "longMode"), entry, end, context);
                var body = new AddressSet(entry, end);
                require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY), "decode " + tag);
                var function = program.getFunctionManager().createFunction("frame", entry, body, SourceType.USER_DEFINED);
                int machine = arm ? 183 : 62;
                ElfImage image = image(tag, machine, true, ByteOrder.LITTLE_ENDIAN, 2, 0, 0, 0x9000);
                byte[] original = image.bytes();
                if (!compiler.equals(arm ? "default" : "gcc")) {
                    rejected(() -> UnwindAbiProfile.select(program, function, image, 0, TaskMonitor.DUMMY));
                    return;
                }
                var selected = UnwindAbiProfile.select(program, function, image, 0, TaskMonitor.DUMMY);
                var instruction = program.getListing().getInstructionAt(entry);
                evidence.append(tag).append(" convention=").append(function.getCallingConventionName())
                    .append(" effective=").append(selected.description().convention())
                    .append(" instruction=").append(instruction).append(" pcode=")
                    .append(Arrays.toString(instruction.getPcode())).append('\n');
                if (!shape.equals("ordinary")) {
                    if (shape.equals("pac-hidden")) require(instruction.getPcode().length == 0, "hidden PAC did not reproduce empty p-code");
                    if (shape.equals("pac-visible")) require(instruction.getPcode().length > 0, "visible PAC has no p-code");
                    if (shape.equals("pac-later")) {
                        selected.requireInstruction(instruction, TaskMonitor.DUMMY);
                        var later = program.getListing().getInstructionAfter(entry);
                        require(later.getMnemonicString().equals("paciasp") && later.getPcode().length == 0,
                            "later hidden PAC fixture did not decode as intended");
                        rejected(() -> selected.requireInstruction(later, TaskMonitor.DUMMY));
                    }
                    else rejected(() -> selected.requireInstruction(instruction, TaskMonitor.DUMMY));
                    rejected(() -> GhidraUnwindInstructions.capture(program, function,
                        selected::requireInstruction, ignored -> null, TaskMonitor.DUMMY));
                    return;
                }
                for (var item : program.getListing().getInstructions(body, true)) selected.requireInstruction(item, TaskMonitor.DUMMY);
                var captured = GhidraUnwindInstructions.capture(program, function,
                    selected::requireInstruction, ignored -> null, TaskMonitor.DUMMY);
                var recovered = UnwindFlow.analyze(captured.graph(), entry, selected.entry(), selected.stackPointer(), () -> false);
                var returned = recovered.after().get(program.getListing().getInstructionContaining(end).getAddress());
                require(returned.values().get(selected.stackPointer()).equals(
                    new StackAddress(selected.description().returnStackAdjustment(), 8)), "ordinary return stack adjustment");
                require(returned.values().get(selected.programCounter()).equals(new ReturnAddress(8)), "ordinary return target identity");
                for (int number : selected.description().calleeSaved()) {
                    require(returned.values().get(selected.registers().get(number)).equals(new Incoming(number, 8)),
                        "ordinary return failed to restore incoming register " + number);
                }
                require(selected.entry().values().get(selected.stackPointer()).equals(new StackAddress(0, 8)), "wrong entry stack identity");
                require(arm ? selected.entry().values().get(selected.registers().get(30)).equals(new ReturnAddress(8)) :
                    selected.entry().memory().get(new Slot(0, 8)).equals(new ReturnAddress(8)), "wrong return-address origin");
                require(!selected.entry().values().containsKey(selected.programCounter()), "current PC became incoming caller value");
                if (arm) require(!selected.calleeSavedCells().contains(selected.registers().get(30)), "Ghidra unaffected LR leaked into call preservation");
                require(Arrays.equals(original, image.bytes()), "selection changed input ELF");
                ElfImage shared = image(tag + "-shared", machine, true, ByteOrder.LITTLE_ENDIAN, 3, 0, 3, 0);
                require(UnwindAbiProfile.select(program, function, shared, 0, TaskMonitor.DUMMY).entry().equals(selected.entry()),
                    "linked shared-image metadata changed entry state");
                int[] capturePolls = {0};
                var captureCounting = new TaskMonitorAdapter(true) {
                    @Override public void checkCancelled() { capturePolls[0]++; }
                };
                GhidraUnwindInstructions.capture(program, function, selected::requireInstruction, ignored -> null, captureCounting);
                for (int limit = 1; limit <= capturePolls[0]; limit++) {
                    int stop = limit; int[] seen = {0};
                    var cancelled = new TaskMonitorAdapter(true) {
                        @Override public void checkCancelled() throws CancelledException { if (++seen[0] == stop) throw new CancelledException(); }
                    };
                    try {
                        GhidraUnwindInstructions.capture(program, function, selected::requireInstruction, ignored -> null, cancelled);
                        throw new AssertionError("guarded capture ignored cancellation");
                    }
                    catch (CancelledException expected) { checks++; }
                }
                require(GhidraUnwindInstructions.capture(program, function, selected::requireInstruction, ignored -> null, TaskMonitor.DUMMY)
                    .equals(captured), "guarded capture cancellation changed retry");
                function.setCustomVariableStorage(true);
                rejected(() -> UnwindAbiProfile.select(program, function, image, 0, TaskMonitor.DUMMY));
                function.setCustomVariableStorage(false);
                function.setCallFixup("unproved_fixture_fixup");
                rejected(() -> UnwindAbiProfile.select(program, function, image, 0, TaskMonitor.DUMMY));
                function.setCallFixup(null);
                function.setStackPurgeSize(16);
                rejected(() -> UnwindAbiProfile.select(program, function, image, 0, TaskMonitor.DUMMY));
                function.setStackPurgeSize(0);
                if (!arm) {
                    function.setCallingConvention("MSABI");
                    rejected(() -> UnwindAbiProfile.select(program, function, image, 0, TaskMonitor.DUMMY));
                    function.setCallingConvention("__stdcall");
                }
                for (ElfImage invalid : List.of(
                        image(tag + "-machine", arm ? 62 : 183, true, ByteOrder.LITTLE_ENDIAN, 2, 0, 0, 0x9000),
                        image(tag + "-class", machine, false, ByteOrder.LITTLE_ENDIAN, 2, 0, 0, 0x9000),
                        image(tag + "-order", machine, true, ByteOrder.BIG_ENDIAN, 2, 0, 0, 0x9000),
                        image(tag + "-type", machine, true, ByteOrder.LITTLE_ENDIAN, 1, 0, 0, 0x9000),
                        image(tag + "-flags", machine, true, ByteOrder.LITTLE_ENDIAN, 2, 1, 0, 0x9000),
                        image(tag + "-osabi", machine, true, ByteOrder.LITTLE_ENDIAN, 2, 0, 9, 0x9000),
                        image(tag + "-entry", machine, true, ByteOrder.LITTLE_ENDIAN, 2, 0, 0, 0x1000))) {
                    rejected(() -> UnwindAbiProfile.select(program, function, invalid, 0, TaskMonitor.DUMMY));
                }
                program.setImageBase(program.getImageBase().add(0x400000), true);
                require(UnwindAbiProfile.select(program, function, image, 0x400000, TaskMonitor.DUMMY).entry().equals(selected.entry()),
                    "rebase changed ordinary ABI seed");
                ElfImage processEntry = image(tag + "-rebased-entry", machine, true, ByteOrder.LITTLE_ENDIAN, 2, 0, 0, 0x1000);
                rejected(() -> UnwindAbiProfile.select(program, function, processEntry, 0x400000, TaskMonitor.DUMMY));
                int[] polls = {0};
                var counting = new TaskMonitorAdapter(true) { @Override public void checkCancelled() { polls[0]++; } };
                UnwindAbiProfile.select(program, function, image, 0x400000, counting);
                for (int limit = 1; limit <= polls[0]; limit++) {
                    int stop = limit; int[] seen = {0};
                    var cancelled = new TaskMonitorAdapter(true) {
                        @Override public void checkCancelled() throws CancelledException { if (++seen[0] == stop) throw new CancelledException(); }
                    };
                    try {
                        UnwindAbiProfile.select(program, function, image, 0x400000, cancelled);
                        throw new AssertionError("selection ignored cancellation");
                    }
                    catch (CancelledException expected) { checks++; }
                }
                require(UnwindAbiProfile.select(program, function, image, 0x400000, TaskMonitor.DUMMY).entry().equals(selected.entry()),
                    "selection cancellation contaminated retry");
            }
            finally { program.endTransaction(transaction, false); }
        }
        finally { program.release(owner); }
    }
}
