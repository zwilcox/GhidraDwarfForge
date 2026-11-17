package ghidradwarfforge;

import java.io.File;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;

/** Raw affine-operation contracts over declared N32 spaces; not new machine-code support. */
public final class TruncatedAffineBoundarySmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        run();
    }

    static void run() throws Exception {
        for (boolean big : new boolean[] {false, true}) {
            try (var fixture = new Fixture(big)) { fixture.check(); }
        }
        System.out.println("truncated-affine-boundaries=PASS checks=" + checks);
    }

    private static final class Fixture implements AutoCloseable {
        final Object owner = new Object();
        final ProgramDB program;
        final Function function;
        final Address entry;
        final List<Instruction> instructions = new ArrayList<>();
        final Varnode pointer, temporary, unknown;
        final boolean big;

        Fixture(boolean big) throws Exception {
            this.big = big;
            var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(
                "MIPS:" + (big ? "BE" : "LE") + ":64:64-32addr"));
            program = new ProgramDB("truncated-affine-contract", language,
                language.getCompilerSpecByID(new CompilerSpecID("n32")), owner);
            entry = language.getDefaultSpace().getAddress(0x1000);
            var bytes = ByteBuffer.allocate(24).order(big ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
            bytes.putInt(0).putInt(0).putInt(0).putInt(0).putInt(0x03e00008).putInt(0);
            int tx = program.startTransaction("raw affine context");
            try {
                var body = new AddressSet(entry, entry.add(23));
                program.getMemory().createInitializedBlock("code", entry, 24, (byte) 0,
                    TaskMonitor.DUMMY, false).setExecute(true);
                program.getMemory().setBytes(entry, bytes.array());
                require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY), "decode context");
                function = program.getFunctionManager().createFunction("affine", entry, body, SourceType.USER_DEFINED);
                program.getListing().getInstructions(body, true).forEach(instructions::add);
            }
            finally { program.endTransaction(tx, true); }
            require(instructions.size() == 6, "six decoded instructions required");
            var sp = program.getCompilerSpec().getStackPointer();
            pointer = new Varnode(sp.getAddress(), sp.getMinimumByteSize());
            require(pointer.getSize() == 8, "N32 fixture requires a wide stack register");
            temporary = new Varnode(program.getAddressFactory().getUniqueSpace().getAddress(0x100), 8);
            unknown = new Varnode(program.getRegister("a0").getAddress(), 8);
        }

        void check() throws Exception {
            long modification = program.getModificationNumber();
            for (int opcode : new int[] {PcodeOp.INT_ADD, PcodeOp.INT_SUB}) {
                for (long delta : new long[] {0, 1, -1, 16, -16, Integer.MIN_VALUE, Integer.MAX_VALUE,
                        0xffff_ffffL, 0x1_0000_0000L, 0x1_0000_0001L, Long.MIN_VALUE, Long.MAX_VALUE}) {
                    BigInteger initial = BigInteger.valueOf(-16);
                    BigInteger expected = opcode == PcodeOp.INT_ADD ? initial.add(BigInteger.valueOf(delta)) :
                        initial.subtract(BigInteger.valueOf(delta));
                    int low = expected.mod(BigInteger.ONE.shiftLeft(32)).intValue();
                    test(low, op(opcode, pointer, pointer, constant(delta, 8)));
                    if (opcode == PcodeOp.INT_ADD) test(low, op(opcode, pointer, constant(delta, 8), pointer));
                    else test(null, op(opcode, pointer, constant(delta, 8), pointer));
                }
                for (Varnode[] inputs : List.of(new Varnode[0], new Varnode[] {pointer},
                        new Varnode[] {pointer, constant(1, 8), pointer}, new Varnode[] {null, constant(1, 8)},
                        new Varnode[] {pointer, null}, new Varnode[] {unknown, constant(1, 8)},
                        new Varnode[] {pointer, unknown})) {
                    test(null, op(opcode, pointer, inputs));
                }
                for (int width : new int[] {1, 2, 4, 16}) {
                    test(null, op(opcode, pointer, low(width), constant(1, 8)));
                    test(null, op(opcode, pointer, pointer, constant(1, width)));
                }
            }
            for (int opcode : new int[] {PcodeOp.COPY, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT}) {
                for (int width : new int[] {1, 2, 4, 8, 16}) {
                    boolean admitted = opcode == PcodeOp.COPY ? width == 8 : width == 4;
                    test(admitted ? -16 : null, op(opcode, pointer, low(width)));
                }
                test(null, op(opcode, pointer, new Varnode[] {null}));
                test(null, op(opcode, pointer));
                test(null, op(opcode, pointer, pointer, pointer));
            }
            for (long removed : new long[] {-1, 0, 1, 4, Long.MAX_VALUE}) {
                var narrowed = new Varnode(temporary.getAddress(), 4);
                test(removed == 0 ? -16 : null, op(PcodeOp.SUBPIECE, narrowed, pointer, constant(removed, 4)),
                    op(PcodeOp.INT_ZEXT, pointer, narrowed));
            }
            var narrow = new Varnode(temporary.getAddress(), 4);
            for (Varnode[] inputs : List.of(new Varnode[0], new Varnode[] {pointer},
                    new Varnode[] {null, constant(0, 4)}, new Varnode[] {pointer, null},
                    new Varnode[] {pointer, unknown}, new Varnode[] {low(2), constant(0, 4)})) {
                test(null, op(PcodeOp.SUBPIECE, narrow, inputs), op(PcodeOp.INT_ZEXT, pointer, narrow));
            }
            test(-16, op(PcodeOp.COPY, temporary, pointer), op(PcodeOp.COPY, pointer, temporary));
            testAcross(null, new PcodeOp[] {op(PcodeOp.COPY, temporary, pointer)},
                new PcodeOp[] {op(PcodeOp.COPY, pointer, temporary)});
            test(-16, op(PcodeOp.COPY, unknown, pointer));
            test(null, op(PcodeOp.COPY, low(2), new Varnode(unknown.getAddress(), 2)));
            test(null, op(PcodeOp.INT_XOR, pointer, pointer, pointer));
            require(program.getModificationNumber() == modification, "affine proof modified saved program");
        }

        Varnode low(int width) {
            return new Varnode(pointer.getAddress().add(big ? 8 - width : 0), width);
        }

        Varnode constant(long value, int width) {
            return new Varnode(program.getAddressFactory().getConstantSpace().getAddress(value), width);
        }

        PcodeOp op(int opcode, Varnode output, Varnode... inputs) {
            return new PcodeOp(entry.add(4), 0, opcode, inputs, output);
        }

        void test(Integer expected, PcodeOp... operations) throws Exception {
            testAcross(expected, operations, new PcodeOp[0]);
        }

        void testAcross(Integer expected, PcodeOp[] first, PcodeOp[] second) throws Exception {
            var selected = new ArrayList<>(instructions);
            PcodeOp[][] code = {new PcodeOp[] {op(PcodeOp.INT_ADD, pointer, pointer, constant(-16, 8))}, first, second};
            for (int i = 0; i < code.length; i++) {
                Instruction original = instructions.get(i);
                PcodeOp[] replacement = code[i];
                selected.set(i, (Instruction) Proxy.newProxyInstance(Instruction.class.getClassLoader(),
                    new Class<?>[] {Instruction.class}, (proxy, method, args) -> method.getName().equals("getPcode") ?
                        replacement : method.invoke(original, args)));
            }
            Listing listing = (Listing) Proxy.newProxyInstance(Listing.class.getClassLoader(),
                new Class<?>[] {Listing.class}, (proxy, method, args) -> {
                    if (!method.getName().equals("getInstructions")) throw new AssertionError("unexpected listing API " + method);
                    Iterator<Instruction> iterator = selected.iterator();
                    return new InstructionIterator() {
                        public boolean hasNext() { return iterator.hasNext(); }
                        public Instruction next() { return iterator.next(); }
                        public Iterator<Instruction> iterator() { return this; }
                    };
                });
            Program view = (Program) Proxy.newProxyInstance(Program.class.getClassLoader(), new Class<?>[] {Program.class},
                (proxy, method, args) -> method.getName().equals("getListing") ? listing : method.invoke(program, args));
            Function ownerView = (Function) Proxy.newProxyInstance(Function.class.getClassLoader(), new Class<?>[] {Function.class},
                (proxy, method, args) -> method.getName().equals("getProgram") ? view : method.invoke(function, args));
            try {
                var result = TruncatedStackDepth.prove(view, ownerView, program.getCompilerSpec().getStackPointer(), TaskMonitor.DUMMY);
                require(result.size() == 6 && result.get(entry) == 0 && result.get(entry.add(4)) == -16,
                    "raw affine fixture lost its independent initial depth");
                int wanted = expected == null ? Function.UNKNOWN_STACK_DEPTH_CHANGE : expected;
                require(result.get(entry.add(12)) == wanted, "wrong low-address depth: expected " + wanted +
                    " got " + result.get(entry.add(12)) + " first=" + java.util.Arrays.toString(first));
            }
            catch (RuntimeException failure) { throw new AssertionError("invalid affine operands must not crash proof", failure); }
        }

        @Override public void close() {
            try { program.flushEvents(); }
            finally { program.release(owner); }
        }
    }

    private static void require(boolean condition, String reason) {
        checks++;
        if (!condition) throw new AssertionError(reason);
    }
}
