package ghidradwarfforge;

import java.io.File;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;

/** Raw control contracts through the decoder; not new processor support evidence. */
public final class RegisterControlBoundarySmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        run();
    }

    static void run() throws Exception {
        for (String language : List.of("x86:LE:32:default", "x86:LE:64:default", "AARCH64:LE:64:v8A")) {
            try (var fixture = new Fixture(language)) { fixture.check(); }
        }
        System.out.println("register-control-boundaries=PASS checks=" + checks);
    }

    private static final class Fixture implements AutoCloseable {
        final Object owner = new Object();
        final ProgramDB program;
        final Function function;
        final List<Instruction> instructions = new ArrayList<>();
        final Address entry, destination;
        final Varnode target, condition, output, constantTarget, returnTarget;
        final byte[] bytes;

        Fixture(String id) throws Exception {
            var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(id));
            program = new ProgramDB("raw-control-contract", language, language.getDefaultCompilerSpec(), owner);
            entry = language.getDefaultSpace().getAddress(0x1000);
            bytes = HexFormat.of().parseHex(id.startsWith("x86") ? "9090c3" : "1f2003d51f2003d5c0035fd6");
            int tx = program.startTransaction("decoder context");
            try {
                var body = new AddressSet(entry, entry.add(bytes.length - 1));
                program.getMemory().createInitializedBlock("code", entry, bytes.length, (byte) 0,
                    TaskMonitor.DUMMY, false).setExecute(true);
                program.getMemory().setBytes(entry, bytes);
                require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY), "decode base instructions");
                function = program.getFunctionManager().createFunction("control", entry, body, SourceType.USER_DEFINED);
                program.getListing().getInstructions(body, true).forEach(instructions::add);
            }
            finally { program.endTransaction(tx, true); }
            require(instructions.size() == 3, "complete three-instruction context");
            destination = instructions.getLast().getAddress();
            int pointer = entry.getAddressSpace().getPointerSize();
            target = new Varnode(destination, pointer);
            var register = program.getRegister(id.startsWith("x86") ? "EAX" : "w0");
            condition = new Varnode(register.getAddress(), 1);
            output = new Varnode(register.getAddress(), 4);
            returnTarget = new Varnode(register.getAddress(), pointer);
            constantTarget = new Varnode(program.getAddressFactory().getConstantSpace().getAddress(2), pointer);
        }

        void check() throws Exception {
            long modification = program.getModificationNumber();
            require(RegisterDefinitionFlow.decodedInstructions(program, function, false, TaskMonitor.DUMMY).size() == 3,
                "original body must remain admissible");
            for (boolean conditional : new boolean[] {false, true}) {
                int opcode = conditional ? PcodeOp.CBRANCH : PcodeOp.BRANCH;
                var flow = conditional ? RefType.CONDITIONAL_JUMP : RefType.UNCONDITIONAL_JUMP;
                Address fallthrough = conditional ? instructions.get(1).getAddress() : null;
                Varnode[] inputs = conditional ? new Varnode[] {target, condition} : new Varnode[] {target};
                var good = op(opcode, inputs, null);
                test(true, flow, fallthrough, new Address[] {destination}, good);
                test(false, flow, fallthrough, new Address[] {destination}, op(opcode, inputs, output));
                test(false, flow, fallthrough, new Address[] {destination}, op(opcode, new Varnode[0], null));
                test(false, flow, fallthrough, new Address[] {destination}, op(opcode,
                    conditional ? new Varnode[] {null, condition} : new Varnode[] {null}, null));
                test(false, flow, fallthrough, new Address[] {destination}, op(opcode,
                    conditional ? new Varnode[] {constantTarget, condition} : new Varnode[] {constantTarget}, null));
                test(false, flow, fallthrough, new Address[] {destination}, op(opcode,
                    conditional ? new Varnode[] {target} : new Varnode[] {target, condition}, null));
                test(false, flow, fallthrough, new Address[] {destination}, good, op(PcodeOp.COPY,
                    new Varnode[] {output}, output));
                test(false, flow, fallthrough, new Address[] {destination}, good, good);
                test(false, flow, fallthrough, null, good);
                test(false, flow, fallthrough, new Address[0], good);
                test(false, flow, fallthrough, new Address[] {destination, instructions.get(1).getAddress()}, good);
                test(false, flow, fallthrough, new Address[] {instructions.get(1).getAddress()}, good);
                test(false, RefType.FALL_THROUGH, instructions.get(1).getAddress(), new Address[0], good);
                test(false, conditional ? RefType.UNCONDITIONAL_JUMP : RefType.CONDITIONAL_JUMP,
                    conditional ? null : instructions.get(1).getAddress(), new Address[] {destination}, good);
                if (conditional) {
                    test(false, flow, fallthrough, new Address[] {destination}, op(opcode, new Varnode[] {target, null}, null));
                    for (int width : new int[] {2, 4, 8}) {
                        test(false, flow, fallthrough, new Address[] {destination}, op(opcode,
                            new Varnode[] {target, new Varnode(condition.getAddress(), width)}, null));
                    }
                }
            }
            var returning = op(PcodeOp.RETURN, new Varnode[] {returnTarget}, null);
            test(true, RefType.TERMINATOR, null, new Address[0], returning);
            test(false, RefType.TERMINATOR, null, new Address[0], op(PcodeOp.RETURN, new Varnode[0], null));
            test(false, RefType.TERMINATOR, null, new Address[0], op(PcodeOp.RETURN, new Varnode[] {null}, null));
            test(false, RefType.TERMINATOR, null, new Address[0], op(PcodeOp.RETURN,
                new Varnode[] {returnTarget, returnTarget}, null));
            test(false, RefType.TERMINATOR, null, new Address[0], op(PcodeOp.RETURN, new Varnode[] {returnTarget}, output));
            for (int width : new int[] {1, 2, 4, 8, 16}) {
                if (width != returnTarget.getSize()) test(false, RefType.TERMINATOR, null, new Address[0],
                    op(PcodeOp.RETURN, new Varnode[] {new Varnode(returnTarget.getAddress(), width)}, null));
            }
            test(false, RefType.FALL_THROUGH, instructions.get(1).getAddress(), new Address[0], returning);
            test(false, RefType.TERMINATOR, null, new Address[0], returning, returning);
            test(false, RefType.TERMINATOR, null, new Address[0], returning,
                op(PcodeOp.COPY, new Varnode[] {output}, output));
            require(program.getModificationNumber() == modification, "classification changed saved program");
            byte[] after = new byte[bytes.length];
            program.getMemory().getBytes(entry, after);
            require(java.util.Arrays.equals(bytes, after), "classification changed executable bytes");
        }

        PcodeOp op(int opcode, Varnode[] inputs, Varnode result) {
            return new PcodeOp(entry, 0, opcode, inputs, result);
        }

        void test(boolean expected, RefType flow, Address fallthrough, Address[] defaults, PcodeOp... code) throws Exception {
            Instruction original = instructions.getFirst();
            var decorated = (Instruction) Proxy.newProxyInstance(Instruction.class.getClassLoader(),
                new Class<?>[] {Instruction.class}, (proxy, method, arguments) -> switch (method.getName()) {
                    case "getPcode" -> code;
                    case "getFlowType" -> flow;
                    case "getFallThrough" -> fallthrough;
                    case "getDefaultFlows", "getFlows" -> defaults;
                    default -> method.invoke(original, arguments);
                });
            var selected = new ArrayList<>(instructions);
            selected.set(0, decorated);
            Listing listing = (Listing) Proxy.newProxyInstance(Listing.class.getClassLoader(),
                new Class<?>[] {Listing.class}, (proxy, method, arguments) -> {
                    if (!method.getName().equals("getInstructions")) throw new AssertionError("unexpected listing API " + method);
                    Iterator<Instruction> iterator = selected.iterator();
                    return new InstructionIterator() {
                        public boolean hasNext() { return iterator.hasNext(); }
                        public Instruction next() { return iterator.next(); }
                        public Iterator<Instruction> iterator() { return this; }
                    };
                });
            var view = (Program) Proxy.newProxyInstance(Program.class.getClassLoader(), new Class<?>[] {Program.class},
                (proxy, method, arguments) -> method.getName().equals("getListing") ? listing : method.invoke(program, arguments));
            try {
                Map<Address, Instruction> actual = RegisterDefinitionFlow.decodedInstructions(view, function, false, TaskMonitor.DUMMY);
                require(expected ? actual.size() == 3 : actual.isEmpty(), "unsafe raw control admitted or valid transfer refused: " +
                    flow + " " + java.util.Arrays.toString(code));
            }
            catch (RuntimeException failure) { throw new AssertionError("raw control must be classified without crashing", failure); }
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
