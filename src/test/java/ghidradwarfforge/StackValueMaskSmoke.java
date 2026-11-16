package ghidradwarfforge;

import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.RegisterStorage;

/** Independent finite-width arithmetic checks for the location proof's known-zero facts. */
final class StackValueMaskSmoke {
    private static int checks;
    private static final long[] NOISE = { 0, 1, 0xff, 0x00ffffffL, 0x7fffffffL, 0x80000000L, 0xffffffffL };
    private record Case(String name, int bitOffset, boolean available, Consumer<Code> nuisance) { }

    static int check(ProgramDB program, Instruction template, TargetRegisterMap registers) throws Exception {
        checks = 0;
        var cases = new ArrayList<Case>();
        for (int extension : new int[] { PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT }) {
            for (boolean clearSign : new boolean[] { false, true }) {
                if (extension == PcodeOp.INT_ZEXT && clearSign) continue;
                for (int opcode : new int[] { PcodeOp.INT_LEFT, PcodeOp.INT_RIGHT, PcodeOp.INT_SRIGHT }) {
                    for (int count : new int[] { 0, 1, 8, 24, 25, 32, 63, 64, 65 }) {
                        boolean positive = extension == PcodeOp.INT_ZEXT || clearSign;
                        // The tracked byte occupies bits56..63. Determine whether
                        // the nuisance operand can place any bit in that byte.
                        boolean available = opcode == PcodeOp.INT_LEFT ? count >= 64 ||
                            positive && count <= (clearSign ? 25 : 24) :
                            opcode == PcodeOp.INT_RIGHT ? positive || count >= 8 : positive;
                        cases.add(new Case("extend=" + extension + "/clear-sign=" + clearSign +
                            "/shift=" + opcode + "/count=" + count, 56, available,
                            code -> code.variableNoise(extension, clearSign, opcode, count)));
                    }
                }
            }
        }
        cases.add(new Case("literal-and", 32, true, c -> c.literalNoise(PcodeOp.INT_AND, 0xff, 0x100, 8)));
        cases.add(new Case("literal-or", 32, true, c -> c.literalNoise(PcodeOp.INT_OR, 0xff, 0x100, 8)));
        cases.add(new Case("literal-xor", 32, true, c -> c.literalNoise(PcodeOp.INT_XOR, 0x100000000L, 0x100000000L, 8)));
        cases.add(new Case("literal-add-carry", 32, false, c -> c.literalNoise(PcodeOp.INT_ADD, 0xffffffffL, 1, 8)));
        cases.add(new Case("literal-sub-borrow", 32, false, c -> c.literalNoise(PcodeOp.INT_SUB, 0, 1, 8)));
        cases.add(new Case("literal-multiply", 32, false, c -> c.literalNoise(PcodeOp.INT_MULT, 0x10000, 0x10000, 8)));
        cases.add(new Case("literal-add-wrap32", 32, true, c -> c.literalNoise(PcodeOp.INT_ADD, 0xffffffffL, 1, 4)));
        cases.add(new Case("mask-signed-high-byte", 56, true, c -> c.maskedNoise(PcodeOp.INT_AND, 0x00ffffffffffffffL, true)));
        cases.add(new Case("runtime-or-below-byte", 56, true, c -> c.maskedNoise(PcodeOp.INT_OR, 1L << 48, false)));
        cases.add(new Case("runtime-or-in-byte", 56, false, c -> c.maskedNoise(PcodeOp.INT_OR, 1L << 56, false)));
        cases.add(new Case("runtime-xor-below-byte", 56, true, c -> c.maskedNoise(PcodeOp.INT_XOR, 1L << 48, false)));
        cases.add(new Case("runtime-xor-in-byte", 56, false, c -> c.maskedNoise(PcodeOp.INT_XOR, 1L << 56, false)));
        cases.add(new Case("runtime-add-disjoint", 56, true, c -> c.maskedNoise(PcodeOp.INT_ADD, 1L << 48, false)));
        cases.add(new Case("runtime-add-in-byte", 56, false, c -> c.maskedNoise(PcodeOp.INT_ADD, 1L << 56, false)));
        for (var test : cases) {
            for (int merge : new int[] { PcodeOp.INT_OR, PcodeOp.INT_ADD }) {
                for (boolean reversed : new boolean[] { false, true }) {
                    var code = new Code(program, template);
                    code.op(PcodeOp.INT_ZEXT, code.carrier, code.source);
                    code.op(PcodeOp.INT_LEFT, code.carrier, code.carrier, code.constant(test.bitOffset(), 4));
                    test.nuisance().accept(code);
                    code.op(merge, code.destination, reversed ? code.nuisance : code.carrier,
                        reversed ? code.carrier : code.nuisance);
                    code.op(PcodeOp.COPY, code.source, code.constant(0, 4));
                    String context = test.name() + "/merge=" + merge + "/reversed=" + reversed;
                    var state = StackValueFlow.forIncomingPiece(program, new Varnode(code.source.getAddress(), 1));
                    require(state != null && state.advance(code.instruction(), false, TaskMonitor.DUMMY),
                        "p-code sequence refused " + context);
                    var location = state.location(registers);
                    require(location.available() == test.available(), "wrong availability " + context + ": " + location);
                    if (test.available()) {
                        require(location instanceof RegisterStorage register && register.register().dwarfNumber() == 256 &&
                            register.valueBitOffset() == test.bitOffset() && register.bitSize() == 8,
                            "wrong surviving register byte " + context + ": " + location);
                    }
                    boolean counterexample = false;
                    // Enumerate every tracked byte and sign/carry-boundary nuisance
                    // values. The evaluator uses BigInteger and explicit widths,
                    // independently of the production long masks and proof facts.
                    for (int value = 0; value <= 255; value++) {
                        for (long noise : NOISE) {
                            BigInteger result = evaluate(code, value, noise);
                            int observed = result.shiftRight(test.bitOffset()).and(BigInteger.valueOf(255)).intValue();
                            if (test.available()) require(observed == value, "reported byte was modified " + context);
                            else counterexample |= observed != value;
                        }
                    }
                    if (!test.available()) require(counterexample, "negative fixture has no destructive example " + context);
                }
            }
        }
        System.out.println("stack-value-mask=PASS cases=" + cases.size() * 4 + " checks=" + checks +
            " evaluator=BigInteger raw-pcode=true target=ARM-LE");
        return checks;
    }

    private static final class Code {
        final ProgramDB program;
        final Instruction template;
        final List<PcodeOp> operations = new ArrayList<>();
        final Varnode source, other, destination, carrier, nuisance;
        long next = 0x1000;

        Code(ProgramDB program, Instruction template) {
            this.program = program;
            this.template = template;
            source = new Varnode(program.getRegister("r3").getAddress(), 4);
            other = new Varnode(program.getRegister("r0").getAddress(), 4);
            destination = new Varnode(program.getRegister("d0").getAddress(), 8);
            carrier = unique(8);
            nuisance = unique(8);
        }

        Varnode unique(int bytes) {
            next += 0x100;
            return new Varnode(program.getAddressFactory().getUniqueSpace().getAddress(next), bytes);
        }

        Varnode constant(long value, int bytes) {
            return new Varnode(program.getAddressFactory().getConstantSpace().getAddress(value), bytes);
        }

        void op(int opcode, Varnode output, Varnode... inputs) {
            operations.add(new PcodeOp(template.getAddress(), operations.size(), opcode, inputs, output));
        }

        void variableNoise(int extension, boolean clearSign, int shift, int count) {
            Varnode input = other;
            if (clearSign) {
                input = unique(4);
                op(PcodeOp.INT_AND, input, other, constant(0x7fffffff, 4));
            }
            op(extension, nuisance, input);
            op(shift, nuisance, nuisance, constant(count, 4));
        }

        void literalNoise(int opcode, long first, long second, int width) {
            var value = unique(width);
            op(opcode, value, constant(first, width), constant(second, width));
            op(width == 8 ? PcodeOp.COPY : PcodeOp.INT_ZEXT, nuisance, value);
        }

        void maskedNoise(int opcode, long mask, boolean signed) {
            op(signed ? PcodeOp.INT_SEXT : PcodeOp.INT_ZEXT, nuisance, other);
            op(opcode, nuisance, nuisance, constant(mask, 8));
        }

        Instruction instruction() {
            return (Instruction) Proxy.newProxyInstance(Instruction.class.getClassLoader(), new Class<?>[] {Instruction.class},
                (proxy, method, arguments) -> method.getName().equals("getPcode") ?
                    operations.toArray(PcodeOp[]::new) : method.invoke(template, arguments));
        }
    }

    private static BigInteger evaluate(Code code, int value, long noise) {
        Map<Varnode, BigInteger> values = new HashMap<>();
        values.put(code.source, BigInteger.valueOf((noise & 0xffffff00L) | value));
        values.put(code.other, BigInteger.valueOf(noise));
        for (PcodeOp op : code.operations) {
            var first = read(values, op.getInput(0));
            var second = op.getNumInputs() > 1 ? read(values, op.getInput(1)) : BigInteger.ZERO;
            int width = op.getOutput().getSize() * 8;
            int inputWidth = op.getInput(0).getSize() * 8;
            int shift = second.compareTo(BigInteger.valueOf(width)) >= 0 ? width : second.intValueExact();
            BigInteger result = switch (op.getOpcode()) {
                case PcodeOp.COPY, PcodeOp.INT_ZEXT -> first;
                case PcodeOp.INT_SEXT -> signed(first, inputWidth);
                case PcodeOp.INT_LEFT -> first.shiftLeft(shift);
                case PcodeOp.INT_RIGHT -> first.shiftRight(shift);
                case PcodeOp.INT_SRIGHT -> signed(first, inputWidth).shiftRight(shift);
                case PcodeOp.INT_AND -> first.and(second);
                case PcodeOp.INT_OR -> first.or(second);
                case PcodeOp.INT_XOR -> first.xor(second);
                case PcodeOp.INT_ADD -> first.add(second);
                case PcodeOp.INT_SUB -> first.subtract(second);
                case PcodeOp.INT_MULT -> first.multiply(second);
                default -> throw new AssertionError("unexpected evaluator opcode");
            };
            values.put(op.getOutput(), result.and(mask(width)));
        }
        return values.get(code.destination);
    }

    private static BigInteger signed(BigInteger value, int bits) {
        return value.testBit(bits - 1) ? value.subtract(BigInteger.ONE.shiftLeft(bits)) : value;
    }

    private static BigInteger read(Map<Varnode, BigInteger> values, Varnode node) {
        var result = node.isConstant() ? BigInteger.valueOf(node.getOffset()) : values.get(node);
        if (result == null) throw new AssertionError("reference evaluator read an uninitialized value");
        return result.and(mask(node.getSize() * 8));
    }

    private static BigInteger mask(int bits) { return BigInteger.ONE.shiftLeft(bits).subtract(BigInteger.ONE); }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
