package ghidradwarfforge;

import java.io.File;
import java.util.ArrayList;
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
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/** Real listing inventories: variable-length instructions, gaps, rebases and drift. */
public final class GhidraInstructionEvidenceSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        fixture("x86:LE:64:default", "90b82a000000c3", "90c3", List.of(0L, 1L, 6L, 32L, 33L));
        fixture("AARCH64:LE:64:v8A", "1f2003d51f2003d5c0035fd6", "1f2003d5c0035fd6",
            List.of(0L, 4L, 8L, 32L, 36L));
        fixture("MIPS:BE:32:default", "0000000003e0000800000000", "03e0000800000000",
            List.of(0L, 4L, 8L, 32L, 36L));
        fixture("MIPS:LE:32:default", "000000000800e00300000000", "0800e00300000000",
            List.of(0L, 4L, 8L, 32L, 36L));
        System.out.println("ghidra-instruction-evidence-smoke=PASS profiles=4 checks=" + checks);
    }

    private static void fixture(String languageId, String firstHex, String secondHex,
            List<Long> offsets) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(languageId));
        Object owner = new Object();
        var program = new ProgramDB("coverage", language, language.getDefaultCompilerSpec(), owner);
        try {
            int transaction = program.startTransaction("coverage fixture");
            try {
                var entry = language.getDefaultSpace().getAddress(0x1000);
                var block = program.getMemory().createInitializedBlock("code", entry, 0x80,
                    (byte) 0, TaskMonitor.DUMMY, false);
                block.setExecute(true);
                byte[] first = HexFormat.of().parseHex(firstHex);
                byte[] second = HexFormat.of().parseHex(secondHex);
                program.getMemory().setBytes(entry, first);
                program.getMemory().setBytes(entry.add(32), second);
                var firstDecode = new AddressSet(entry, entry.add(first.length - 1));
                var secondDecode = new AddressSet(entry.add(32), entry.add(32 + second.length - 1));
                require(new DisassembleCommand(entry, firstDecode, true).applyTo(program, TaskMonitor.DUMMY), "first decode");
                require(new DisassembleCommand(entry.add(32), secondDecode, true).applyTo(program, TaskMonitor.DUMMY), "second decode");
                var body = new AddressSet(entry, entry.add(15));
                body.add(entry.add(32), entry.add(43));
                var function = program.getFunctionManager().createFunction("split", entry, body, SourceType.USER_DEFINED);
                program.getSymbolTable().createLabel(entry, "analyst_alias", SourceType.USER_DEFINED);
                program.getFunctionManager().createFunction("empty", entry.add(64),
                    new AddressSet(entry.add(64), entry.add(67)), SourceType.USER_DEFINED);
                var diagnostics = new ArrayList<String>();
                var selected = GhidraFunctionSymbols.extract(program, TaskMonitor.DUMMY, diagnostics::add, 0);
                var inventory = GhidraInstructionEvidence.capture(program, selected, 0,
                    TaskMonitor.DUMMY, diagnostics::add);
                var expected = offsets.stream().map(offset -> 0x1000L + offset).toList();
                require(inventory.size() == 2 && inventory.getFirst().starts().equals(expected),
                    languageId + " exact decoded starts " + inventory);
                require(inventory.getFirst().available() && inventory.getLast().available() &&
                    inventory.getLast().starts().isEmpty(), "known zero inventory distinct from unavailable");
                require(diagnostics.isEmpty(), "valid evidence diagnostics");
                var changedBody = new AddressSet(body);
                changedBody.add(entry.add(44));
                function.setBody(changedBody);
                var changed = GhidraInstructionEvidence.capture(program, selected, 0,
                    TaskMonitor.DUMMY, diagnostics::add);
                require(!changed.getFirst().available() && changed.getFirst().starts().isEmpty() &&
                    changed.getFirst().unavailableReason().contains("body changed"), "body drift unavailable");
                function.setBody(body);
                function.setName("renamed", SourceType.USER_DEFINED);
                var renamed = GhidraInstructionEvidence.capture(program, selected, 0,
                    TaskMonitor.DUMMY, diagnostics::add);
                require(!renamed.getFirst().available(), "stale function identity unavailable");
                function.setName("split", SourceType.USER_DEFINED);
                program.setImageBase(program.getImageBase().add(0x200000), true);
                var rebased = GhidraInstructionEvidence.capture(program, selected, 0x200000,
                    TaskMonitor.DUMMY, diagnostics::add);
                require(rebased.equals(inventory), "rebase keeps link-time evidence stable");
                int[] checkpoints = {0};
                var interrupted = new TaskMonitorAdapter(true) {
                    @Override
                    public void checkCancelled() throws CancelledException {
                        if (++checkpoints[0] == 9) throw new CancelledException();
                    }
                };
                try {
                    GhidraInstructionEvidence.capture(program, selected, 0x200000,
                        interrupted, diagnostics::add);
                    throw new AssertionError("partial inventory escaped cancellation");
                }
                catch (CancelledException expectedCancellation) { checks++; }
                require(checkpoints[0] == 9, "prompt cancellation inside instruction capture");
                var monitor = new TaskMonitorAdapter(true);
                monitor.cancel();
                try {
                    GhidraInstructionEvidence.capture(program, selected, 0x200000, monitor, diagnostics::add);
                    throw new AssertionError("cancellation ignored");
                }
                catch (CancelledException expectedCancellation) { checks++; }
            }
            finally { program.endTransaction(transaction, true); }
        }
        finally { program.release(owner); }
    }

    private static void require(boolean condition, String detail) {
        checks++;
        if (!condition) throw new AssertionError(detail);
    }
}
