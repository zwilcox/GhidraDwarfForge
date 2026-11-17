package ghidradwarfforge;

import java.io.File;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.RegisterStorage;

/** Raw p-code transfer contracts; byte windows and BigInteger provide independent oracles. */
public final class StackTransferShapeSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        check();
    }

    static int check() throws Exception {
        checks = 0;
        Object owner = new Object();
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:64:default"));
        var program = new ProgramDB("transfer-shapes", language, language.getDefaultCompilerSpec(), owner);
        try {
            int tx = program.startTransaction("raw instruction fixture");
            try {
                var entry = language.getDefaultSpace().getAddress(0x1000);
                program.getMemory().createInitializedBlock("code", entry, 1, (byte) 0x90, TaskMonitor.DUMMY, false);
                require(new DisassembleCommand(entry, new AddressSet(entry), false).applyTo(program, TaskMonitor.DUMMY), "NOP decode");
                var template = program.getListing().getInstructionAt(entry);
                long modification = program.getModificationNumber();
                for (int bytes : new int[] {1, 2, 4, 8}) {
                    for (int offset = 0; offset <= 8 - bytes; offset++) {
                        for (int width : new int[] {1, 2, 4, 8}) {
                            for (int removed = 0; removed <= 8 - width; removed++) {
                                var code = new Code(program, template);
                                code.op(PcodeOp.SUBPIECE, code.destination(width), code.source, code.constant(removed, 4));
                                boolean fits = offset >= removed && offset + bytes <= removed + width;
                                code.check(bytes, offset, fits ? offset - removed : -1, "subpiece " + width + "/" + removed);
                            }
                        }
                        for (int opcode : new int[] {PcodeOp.INT_LEFT, PcodeOp.INT_RIGHT, PcodeOp.INT_SRIGHT}) {
                            for (long shift : new long[] {-1, 0, 1, 7, 8, 16, 31, 32, 56, 63, 64, 65, Long.MIN_VALUE}) {
                                var code = new Code(program, template);
                                code.op(opcode, code.destination(8), code.source, code.constant(shift, 8));
                                long moved = offset * 8L + (opcode == PcodeOp.INT_LEFT ? shift : -shift);
                                boolean fits = shift >= 0 && shift < 64 && shift % 8 == 0 &&
                                    moved >= 0 && moved + bytes * 8 <= 64;
                                code.check(bytes, offset, fits ? (int) moved / 8 : -1, "shift " + opcode + "/" + shift);
                                if (fits) {
                                    BigInteger value = BigInteger.ONE.shiftLeft(bytes * 8).subtract(BigInteger.ONE);
                                    BigInteger original = value.shiftLeft(offset * 8);
                                    BigInteger actual = opcode == PcodeOp.INT_LEFT ? original.shiftLeft((int) shift) :
                                        original.shiftRight((int) shift);
                                    require(actual.shiftRight((int) moved).and(value).equals(value), "reference shift lost tracked bits");
                                }
                            }
                        }
                    }
                    for (int low = 1; low < 8; low++) {
                        for (boolean upper : new boolean[] {false, true}) {
                            int width = upper ? 8 - low : low;
                            if (bytes > width) continue;
                            var code = new Code(program, template);
                            var input = new Varnode(code.source.getAddress(), width);
                            code.op(PcodeOp.PIECE, code.destination(8), upper ? input : code.constant(0, 8 - low),
                                upper ? code.constant(0, low) : input);
                            code.check(bytes, 0, upper ? low : 0, "piece " + low + "/" + upper);
                        }
                    }
                }
                invalidShapes(program, template);
                temporaryLifetime(program, template);
                require(program.getModificationNumber() == modification && program.getMemory().getByte(entry) == (byte) 0x90,
                    "proof changed the program or its bytes");
            }
            finally { program.endTransaction(tx, false); }
        }
        finally { program.release(owner); }
        System.out.println("stack-transfer-shapes=PASS checks=" + checks);
        return checks;
    }

    private static void invalidShapes(ProgramDB program, Instruction template) throws Exception {
        for (int opcode : new int[] {PcodeOp.COPY, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT}) {
            for (int width : new int[] {1, 4, 8}) {
                var code = new Code(program, template);
                var input = new Varnode(code.source.getAddress(), 4);
                code.op(opcode, code.destination(width), input);
                boolean valid = opcode == PcodeOp.COPY ? width == 4 : width > 4;
                code.check(1, 0, valid ? 0 : -1, "copy/extension width " + opcode + "/" + width);
            }
        }
        for (long removed : new long[] {-1, 5, 8, Long.MAX_VALUE}) {
            var code = new Code(program, template);
            code.op(PcodeOp.SUBPIECE, code.destination(4), code.source, code.constant(removed, 8));
            code.check(1, 0, -1, "invalid subpiece " + removed);
        }
        for (int opcode : new int[] {PcodeOp.SUBPIECE, PcodeOp.INT_LEFT, PcodeOp.INT_RIGHT, PcodeOp.INT_SRIGHT}) {
            var code = new Code(program, template);
            code.op(opcode, code.destination(8), code.source, new Varnode(program.getRegister("RCX").getAddress(), 8));
            code.check(1, 0, -1, "unknown runtime displacement " + opcode);
        }
        for (int opcode : new int[] {PcodeOp.PIECE, PcodeOp.INT_ADD, PcodeOp.INT_OR}) {
            var code = new Code(program, template);
            code.op(opcode, code.destination(8), code.source, code.constant(0, 4));
            code.check(1, 0, -1, "mismatched operand width " + opcode);
        }
    }

    private static void temporaryLifetime(ProgramDB program, Instruction template) throws Exception {
        var code = new Code(program, template);
        var temporary = new Varnode(program.getAddressFactory().getUniqueSpace().getAddress(0x1000), 8);
        var state = StackValueFlow.forIncomingPiece(program, code.source);
        code.op(PcodeOp.COPY, temporary, code.source);
        require(state.advance(code.instruction(), false, TaskMonitor.DUMMY), "first instruction refused");
        code.operations.clear();
        code.op(PcodeOp.COPY, code.destination(8), temporary);
        code.op(PcodeOp.COPY, code.source, code.constant(0, 8));
        require(state.advance(code.instruction(), false, TaskMonitor.DUMMY), "second instruction refused");
        require(!state.location(TargetRegisterMap.forTarget("x86_64")).available(),
            "unique temporary escaped its instruction and fabricated a surviving value");
    }

    private static final class Code {
        final ProgramDB program;
        final Instruction template;
        final Varnode source;
        final List<PcodeOp> operations = new ArrayList<>();

        Code(ProgramDB program, Instruction template) {
            this.program = program;
            this.template = template;
            source = new Varnode(program.getRegister("RDI").getAddress(), 8);
        }

        Varnode destination(int bytes) { return new Varnode(program.getRegister("RAX").getAddress(), bytes); }
        Varnode constant(long value, int bytes) {
            return new Varnode(program.getAddressFactory().getConstantSpace().getAddress(value), bytes);
        }
        void op(int opcode, Varnode output, Varnode... inputs) {
            operations.add(new PcodeOp(template.getAddress(), operations.size(), opcode, inputs, output));
        }
        Instruction instruction() {
            return (Instruction) Proxy.newProxyInstance(Instruction.class.getClassLoader(), new Class<?>[] {Instruction.class},
                (proxy, method, arguments) -> method.getName().equals("getPcode") ? operations.toArray(PcodeOp[]::new) :
                    method.invoke(template, arguments));
        }
        void check(int bytes, int offset, int expectedOffset, String context) throws Exception {
            context += "/bytes=" + bytes + "/offset=" + offset;
            var state = StackValueFlow.forIncomingPiece(program, new Varnode(source.getAddress().add(offset), bytes));
            require(state != null, "missing initial carrier " + context);
            op(PcodeOp.COPY, source, constant(0, 8));
            require(state.advance(instruction(), false, TaskMonitor.DUMMY), "instruction refused " + context);
            var result = state.location(TargetRegisterMap.forTarget("x86_64"));
            require(result.available() == (expectedOffset >= 0), "wrong availability " + context + ": " + result);
            if (expectedOffset >= 0) require(result instanceof RegisterStorage register && register.register().dwarfNumber() == 0 &&
                register.bitSize() == bytes * 8 && register.valueBitOffset() == expectedOffset * 8,
                "wrong destination byte window " + context + ": " + result);
        }
    }

    private static void require(boolean value, String message) {
        checks++;
        if (!value) throw new AssertionError(message);
    }
}
