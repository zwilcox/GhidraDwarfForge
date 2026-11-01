package ghidradwarfforge;

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
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
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/** Decoded narrow/wide address arithmetic, depth boundaries and unsafe-flow controls. */
public final class TruncatedStackDepthSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (boolean big : List.of(true, false)) {
            for (boolean truncated : List.of(true, false)) {
                for (int middle : List.of(0, 0x0080e82d, 0x33bdfff0, 0xdc9d0000, 0x03a4e82d)) {
                    boolean clobber = middle != 0;
                    var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(
                        "MIPS:" + (big ? "BE" : "LE") + ":64:" + (truncated ? "64-32addr" : "default")));
                    Object owner = new Object();
                    var program = new ProgramDB("truncated-depth", language,
                        language.getCompilerSpecByID(new CompilerSpecID(truncated ? "n32" : "default")), owner);
                    int transaction = program.startTransaction("fixture");
                    try {
                        // addiu stack,-16; nop or unknown COPY/AND/LOAD/ADD;
                        // daddiu stack,8; jr ra; addiu stack,8 (delay slot).
                        var bytes = ByteBuffer.allocate(20).order(big ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
                        bytes.putInt(0x27bdfff0).putInt(middle).putInt(0x67bd0008)
                            .putInt(0x03e00008).putInt(0x27bd0008);
                        var entry = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
                        var block = program.getMemory().createInitializedBlock("code", entry, 20, (byte) 0, TaskMonitor.DUMMY, false);
                        block.setExecute(true);
                        program.getMemory().setBytes(entry, bytes.array());
                        require(new DisassembleCommand(entry, null, true).applyTo(program), "decode failed");
                        var function = program.getFunctionManager().createFunction("value", entry,
                            new AddressSet(entry, entry.add(19)), SourceType.USER_DEFINED);
                        var pointer = program.getCompilerSpec().getStackPointer();
                        var depths = TruncatedStackDepth.prove(program, function, pointer, TaskMonitor.DUMMY);
                        if (!truncated) {
                            require(depths.isEmpty(), "ordinary 64-bit memory accepted");
                            continue;
                        }
                        require(depths.size() == 5, "missing instruction depths");
                        require(depths.get(entry) == 0 && depths.get(entry.add(4)) == -16, "narrow adjustment lost");
                        if (clobber) {
                            require(depths.get(entry.add(8)) == ghidra.program.model.listing.Function.UNKNOWN_STACK_DEPTH_CHANGE &&
                                depths.get(entry.add(12)) == ghidra.program.model.listing.Function.UNKNOWN_STACK_DEPTH_CHANGE,
                                "unknown pointer fabricated");
                        }
                        else {
                            require(depths.get(entry.add(8)) == -16 && depths.get(entry.add(12)) == -8,
                                "wide adjustment lost");
                            var exported = GhidraVariableStorage.stackDepthProfile(program, function, TaskMonitor.DUMMY);
                            require(exported.intervals().stream().anyMatch(row -> row.start() == 0x1004 && row.depth() == -16 && row.known()),
                                "production profile did not use proof");
                        }
                        require(depths.get(entry.add(16)) == ghidra.program.model.listing.Function.UNKNOWN_STACK_DEPTH_CHANGE,
                            "folded delay effect assigned to slot entry");
                        program.getReferenceManager().addMemoryReference(entry.add(0x100), entry.add(5), RefType.UNCONDITIONAL_JUMP,
                            SourceType.USER_DEFINED, 0);
                        require(TruncatedStackDepth.prove(program, function, pointer, TaskMonitor.DUMMY).isEmpty(), "offcut entry accepted");
                        program.getReferenceManager().removeAllReferencesFrom(entry.add(0x100));
                        var instruction = program.getListing().getInstructionAt(entry.add(4));
                        instruction.setFlowOverride(FlowOverride.BRANCH);
                        require(TruncatedStackDepth.prove(program, function, pointer, TaskMonitor.DUMMY).isEmpty(), "flow override accepted");
                        instruction.setFlowOverride(FlowOverride.NONE);
                        TaskMonitorAdapter cancelled = new TaskMonitorAdapter(true);
                        cancelled.cancel();
                        try {
                            TruncatedStackDepth.prove(program, function, pointer, cancelled);
                            throw new AssertionError("cancel ignored");
                        }
                        catch (CancelledException expected) { checks++; }
                        program.getListing().clearCodeUnits(entry.add(4), entry.add(7), false);
                        require(TruncatedStackDepth.prove(program, function, pointer, TaskMonitor.DUMMY).isEmpty(), "undecoded body accepted");
                    }
                    finally {
                        program.endTransaction(transaction, false);
                        program.release(owner);
                    }
                }
            }
        }
        System.out.println("truncated-stack-depth-smoke=PASS checks=" + checks);
    }

    private static void require(boolean condition, String detail) {
        checks++;
        if (!condition) throw new AssertionError(detail);
    }
}
