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
                operandContracts(program, template);
                loadContracts(program, template);
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

    /** Malformed raw transfer descriptions cannot create a carrier after the original is killed. */
    private static void operandContracts(ProgramDB program, Instruction template) throws Exception {
        for (boolean temporary : new boolean[] {false, true}) {
            for (int opcode : new int[] {PcodeOp.COPY, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT,
                    PcodeOp.SUBPIECE, PcodeOp.PIECE, PcodeOp.INT_LEFT, PcodeOp.INT_RIGHT,
                    PcodeOp.INT_SRIGHT, PcodeOp.INT_ADD, PcodeOp.INT_OR}) {
                var base = new Code(program, template);
                var narrow = new Varnode(base.source.getAddress(), 4);
                Varnode[] valid = switch (opcode) {
                    case PcodeOp.COPY -> new Varnode[] {base.source};
                    case PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT -> new Varnode[] {narrow};
                    case PcodeOp.PIECE -> new Varnode[] {base.constant(0, 4), narrow};
                    default -> new Varnode[] {base.source, base.constant(0, 8)};
                };
                var invalid = new ArrayList<Varnode[]>();
                invalid.add(new Varnode[0]);
                if (valid.length > 1) invalid.add(java.util.Arrays.copyOf(valid, valid.length - 1));
                var extra = java.util.Arrays.copyOf(valid, valid.length + 1);
                extra[extra.length - 1] = base.constant(0, 8);
                invalid.add(extra);
                for (int i = 0; i < valid.length; i++) {
                    var absent = valid.clone();
                    absent[i] = null;
                    invalid.add(absent);
                }
                switch (opcode) {
                    case PcodeOp.COPY -> invalid.add(new Varnode[] {narrow});
                    case PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT -> {
                        invalid.add(new Varnode[] {base.source});
                        invalid.add(new Varnode[] {new Varnode(base.source.getAddress(), 16)});
                    }
                    case PcodeOp.PIECE -> invalid.add(new Varnode[] {base.source, narrow});
                    default -> invalid.add(new Varnode[] {narrow, base.constant(0, 8)});
                }
                if (opcode == PcodeOp.INT_ADD || opcode == PcodeOp.INT_OR) {
                    invalid.add(new Varnode[] {base.source, base.constant(0, 4)});
                }
                // Run the valid transfer before and after all invalid shapes. The
                // byte oracle is simply preservation of the original low byte.
                var cases = new ArrayList<Varnode[]>();
                cases.add(valid);
                cases.addAll(invalid);
                cases.add(valid);
                for (int i = 0; i < cases.size(); i++) {
                    var code = new Code(program, template);
                    Varnode destination = temporary ? new Varnode(
                        program.getAddressFactory().getUniqueSpace().getAddress(0x2000), 8) : code.destination(8);
                    code.op(opcode, destination, cases.get(i));
                    if (temporary) code.op(PcodeOp.COPY, code.destination(8), destination);
                    code.check(1, 0, i == 0 || i == cases.size() - 1 ? 0 : -1,
                        "operand contract " + opcode + "/temporary=" + temporary + "/case=" + i);
                }
            }
        }
    }

    /** Preserve only complete contained byte ranges, then erase both original carriers. */
    private static void loadContracts(ProgramDB program, Instruction template) throws Exception {
        for (int bytes : new int[] {1, 2, 4, 8}) {
            for (int width : new int[] {1, 2, 4, 8}) {
                for (long saved : new long[] {-9, -1, 0, 1, 7, 8, 9}) {
                    loadCase(program, template, bytes, width, saved, 0, "valid");
                }
            }
        }
        for (long[] offsets : new long[][] {
                {Long.MIN_VALUE, Long.MIN_VALUE}, {Long.MAX_VALUE - 1, Long.MAX_VALUE - 1},
                {Long.MIN_VALUE, Long.MAX_VALUE - 1}, {Long.MAX_VALUE - 1, Long.MIN_VALUE},
                {Long.MAX_VALUE, 0}}) {
            loadCase(program, template, 1, 1, offsets[0], offsets[1], "valid");
        }
        loadCase(program, template, 1, 8, Long.MIN_VALUE, Long.MAX_VALUE - 1, "valid");
        loadCase(program, template, 8, 8, 0, 0, "value-as-address");
        for (String mode : List.of("missing", "one-operand", "extra-operand", "null-space", "runtime-space",
                "null-address", "narrow-address", "wide-address", "wrong-space", "truncated-space",
                "absolute-address", "unknown-address", "value-as-address", "literal-address", "signed-space")) {
            loadCase(program, template, 1, 8, 0, 0, mode);
        }
    }

    private static void loadCase(ProgramDB program, Instruction template, int bytes, int width,
            long savedOffset, long loadOffset, String mode) throws Exception {
        var code = new Code(program, template);
        var pointer = program.getCompilerSpec().getStackPointer();
        var sp = new Varnode(pointer.getAddress(), 8);
        var unique = program.getAddressFactory().getUniqueSpace();
        var saved = new Varnode(unique.getAddress(0x3000), 8);
        var loaded = new Varnode(unique.getAddress(0x3010), 8);
        long id = Integer.toUnsignedLong(program.getLanguage().getDefaultDataSpace().getSpaceID());
        var space = code.constant(id, 4);
        code.op(PcodeOp.INT_ADD, saved, sp, code.constant(savedOffset, 8));
        code.op(PcodeOp.STORE, null, space, saved, new Varnode(code.source.getAddress(), bytes));
        code.op(PcodeOp.INT_ADD, loaded, sp, code.constant(loadOffset, 8));
        if (mode.equals("value-as-address")) code.op(PcodeOp.COPY, loaded, code.source);
        if (mode.equals("literal-address")) code.op(PcodeOp.COPY, loaded, code.constant(0, 8));
        Varnode[] inputs = switch (mode) {
            case "missing" -> new Varnode[0];
            case "one-operand" -> new Varnode[] {space};
            case "extra-operand" -> new Varnode[] {space, loaded, loaded};
            case "null-space" -> new Varnode[] {null, loaded};
            case "runtime-space" -> new Varnode[] {code.source, loaded};
            case "null-address" -> new Varnode[] {space, null};
            case "narrow-address" -> new Varnode[] {space, new Varnode(loaded.getAddress(), 4)};
            case "wide-address" -> new Varnode[] {space, new Varnode(loaded.getAddress(), 16)};
            case "wrong-space" -> new Varnode[] {code.constant(id + 1, 4), loaded};
            case "truncated-space" -> new Varnode[] {code.constant(id | (1L << 40), 8), loaded};
            case "absolute-address" -> new Varnode[] {space, code.constant(0, 8)};
            case "unknown-address" -> new Varnode[] {space, new Varnode(program.getRegister("RCX").getAddress(), 8)};
            case "signed-space" -> new Varnode[] {code.constant((int) id, 8), loaded};
            default -> new Varnode[] {space, loaded};
        };
        code.op(PcodeOp.LOAD, code.destination(width), inputs);
        // Remove the saved copy after loading. check() also overwrites RDI, so
        // only the loaded register can establish availability in this assertion.
        code.op(PcodeOp.STORE, null, space, saved, code.constant(0, bytes));
        BigInteger start = BigInteger.valueOf(savedOffset);
        BigInteger finish = start.add(BigInteger.valueOf(bytes));
        BigInteger displacement = start.subtract(BigInteger.valueOf(loadOffset));
        boolean preserved = (mode.equals("valid") || mode.equals("signed-space")) &&
            finish.compareTo(BigInteger.valueOf(Long.MAX_VALUE)) <= 0 &&
            displacement.signum() >= 0 && displacement.compareTo(BigInteger.valueOf(width - bytes)) <= 0;
        code.check(bytes, 0, preserved ? displacement.intValueExact() : -1,
            "load " + mode + "/width=" + width + "/saved=" + savedOffset + "/address=" + loadOffset);
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
