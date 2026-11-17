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
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/** Decoded narrow/wide address arithmetic, depth boundaries and unsafe-flow controls. */
public final class TruncatedStackDepthSmoke {
    private static int checks;
    private record Middle(int word, boolean known, String mnemonic) { }
    private static final List<Middle> MIDDLES = List.of(
        new Middle(0, true, "nop"),
        new Middle(0x0080e82d, false, null),
        new Middle(0x33bdfff0, false, null),
        new Middle(0xdc9d0000, false, null),
        new Middle(0x03a4e82d, false, null),
        new Middle(0x03a0e823, true, "subu"),
        new Middle(0x03a0e82f, true, "dsubu"),
        new Middle(0x001de821, true, "move"),
        new Middle(0x001de82d, true, "daddu"),
        new Middle(0x001de823, false, "subu"),
        new Middle(0x001de82f, false, "dsubu"),
        new Middle(0x03a0e821, true, "move"),
        new Middle(0x03a0e82d, true, "daddu"),
        new Middle(0x001de83c, false, "dsll32"),
        new Middle(0x001de83e, false, "dsrl32"),
        // These shifts by zero are identities, but the current affine proof omits them.
        new Middle(0x001de800, false, "sll"),
        new Middle(0x001de838, false, "dsll"));

    public static void main(String[] args) throws Exception {
        checks += StackCoordinateProjectionSmoke.check();
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (boolean big : List.of(true, false)) {
            for (boolean truncated : List.of(true, false)) {
                for (Middle middle : MIDDLES) {
                    var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(
                        "MIPS:" + (big ? "BE" : "LE") + ":64:" + (truncated ? "64-32addr" : "default")));
                    Object owner = new Object();
                    var program = new ProgramDB("truncated-depth", language,
                        language.getCompilerSpecByID(new CompilerSpecID(truncated ? "n32" : "default")), owner);
                    int transaction = program.startTransaction("fixture");
                    try {
                        // addiu stack,-16; selected decoded middle instruction;
                        // daddiu stack,8; jr ra; addiu stack,8 (delay slot).
                        var bytes = ByteBuffer.allocate(20).order(big ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
                        bytes.putInt(0x27bdfff0).putInt(middle.word()).putInt(0x67bd0008)
                            .putInt(0x03e00008).putInt(0x27bd0008);
                        var entry = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
                        var block = program.getMemory().createInitializedBlock("code", entry, 20, (byte) 0, TaskMonitor.DUMMY, false);
                        block.setExecute(true);
                        program.getMemory().setBytes(entry, bytes.array());
                        require(new DisassembleCommand(entry, null, true).applyTo(program), "decode failed");
                        var function = program.getFunctionManager().createFunction("value", entry,
                            new AddressSet(entry, entry.add(19)), SourceType.USER_DEFINED);
                        var pointer = program.getCompilerSpec().getStackPointer();
                        var middleInstruction = program.getListing().getInstructionAt(entry.add(4));
                        require(middleInstruction != null && middleInstruction.getLength() == 4,
                            "middle instruction not decoded at exact boundary: " + middle);
                        if (middle.mnemonic() != null) require(middleInstruction.getMnemonicString().equals(middle.mnemonic()),
                            "unexpected decoded instruction: " + middle + " " + middleInstruction);
                        var depths = TruncatedStackDepth.prove(program, function, pointer, TaskMonitor.DUMMY);
                        if (!truncated) {
                            require(depths.isEmpty(), "ordinary 64-bit memory accepted");
                            continue;
                        }
                        require(depths.size() == 5, "missing instruction depths");
                        require(depths.get(entry) == 0 && depths.get(entry.add(4)) == -16, "narrow adjustment lost");
                        if (!middle.known()) {
                            require(depths.get(entry.add(8)) == ghidra.program.model.listing.Function.UNKNOWN_STACK_DEPTH_CHANGE &&
                                depths.get(entry.add(12)) == ghidra.program.model.listing.Function.UNKNOWN_STACK_DEPTH_CHANGE,
                                "unknown pointer fabricated");
                            // Conservatively unknown instructions must remain unknown in the public profile too.
                            var profile = GhidraVariableStorage.stackDepthProfile(program, function, TaskMonitor.DUMMY);
                            require(profile.intervals().stream().anyMatch(row -> row.start() <= 0x1008 &&
                                row.end() > 0x1008 && !row.known()), "public profile invented a depth after " + middle);
                        }
                        else {
                            require(depths.get(entry.add(8)) == -16 && depths.get(entry.add(12)) == -8,
                                "wide adjustment lost");
                            var exported = GhidraVariableStorage.stackDepthProfile(program, function, TaskMonitor.DUMMY);
                            require(exported.intervals().stream().anyMatch(row -> row.start() == 0x1004 && row.depth() == -16 && row.known()),
                                "production profile did not use proof");
                            concreteIdentity(depths.get(entry.add(8)), depths.get(entry.add(12)), middle);
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
                        if (middle.word() == 0) {
                            var originalBody = new AddressSet(function.getBody());
                            var split = new AddressSet(originalBody);
                            split.deleteRange(entry.add(4), entry.add(7));
                            function.setBody(split);
                            require(TruncatedStackDepth.prove(program, function, pointer, TaskMonitor.DUMMY).isEmpty(),
                                "discontiguous body acquired one linear depth proof");
                            function.setBody(originalBody);
                            var preceding = program.getMemory().createInitializedBlock("preceding", entry.subtract(4),
                                4, (byte) 0, TaskMonitor.DUMMY, false);
                            preceding.setExecute(true);
                            require(new DisassembleCommand(entry.subtract(4), new AddressSet(entry.subtract(4), entry.subtract(1)),
                                false).applyTo(program), "preceding NOP did not decode");
                            function.setBody(new AddressSet(entry.subtract(4), entry.add(19)));
                            require(TruncatedStackDepth.prove(program, function, pointer, TaskMonitor.DUMMY).isEmpty(),
                                "instructions before function entry acquired entry-relative depth");
                            function.setBody(originalBody);
                            cancellationBoundaries(program, function, pointer, depths);
                        }
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

    private static void cancellationBoundaries(ProgramDB program, Function function,
            ghidra.program.model.lang.Register pointer,
            java.util.Map<ghidra.program.model.address.Address, Integer> expected) throws Exception {
        var count = new CountingMonitor(Integer.MAX_VALUE);
        require(TruncatedStackDepth.prove(program, function, pointer, count).equals(expected), "counting monitor changed proof");
        long modification = program.getModificationNumber();
        var body = new AddressSet(function.getBody());
        for (int boundary = 1; boundary <= count.calls; boundary++) {
            var monitor = new CountingMonitor(boundary);
            try {
                TruncatedStackDepth.prove(program, function, pointer, monitor);
                throw new AssertionError("cancellation ignored at proof boundary " + boundary);
            }
            catch (CancelledException failure) {
                require(failure == monitor.failure && monitor.calls == boundary, "cancellation identity or boundary changed");
            }
            require(program.getModificationNumber() == modification && function.getBody().equals(body),
                "cancelled depth proof changed analyzed program");
            require(TruncatedStackDepth.prove(program, function, pointer, TaskMonitor.DUMMY).equals(expected),
                "cancelled depth proof poisoned a subsequent result");
        }
    }

    private static final class CountingMonitor extends TaskMonitorAdapter {
        private final int stop;
        private final CancelledException failure = new CancelledException();
        private int calls;

        CountingMonitor(int stop) { super(true); this.stop = stop; }

        @Override
        public void checkCancelled() throws CancelledException {
            if (++calls == stop) throw failure;
        }
    }

    /** Independent low-address ISA arithmetic, including carry and sign boundaries. */
    private static void concreteIdentity(int middleDepth, int nextDepth, Middle middle) {
        for (long initial : new long[] {0, 1, 15, 16, 0x7fffffffL, 0x80000000L, 0xffffffffL}) {
            // ADDIU uses a sign-extended word result even in the 64-bit register model.
            long afterFirst = (int) (initial - 16);
            long afterMiddle = switch (middle.word()) {
                case 0, 0x001de821, 0x03a0e821 -> afterFirst;
                case 0x03a0e823 -> (int) afterFirst; // SUBU with zero, word result.
                case 0x03a0e82f -> afterFirst - 0;   // DSUBU with zero.
                case 0x001de82d -> 0 + afterFirst;   // DADDU, constant first.
                case 0x03a0e82d -> afterFirst + 0;   // DADDU, constant last.
                default -> throw new AssertionError("unexpected identity fixture " + middle);
            };
            require((int) (afterMiddle - initial) == middleDepth,
                "middle depth disagrees with low-address ISA arithmetic " + middle);
            require((int) (afterMiddle + 8 - initial) == nextDepth,
                "following depth disagrees with low-address ISA arithmetic " + middle);
        }
    }

    private static void require(boolean condition, String detail) {
        checks++;
        if (!condition) throw new AssertionError(detail);
    }
}
