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
        int wideCases = wideCarriers(program, template, registers);
        int overlappingCases = overlappingMerges(program, template, registers);
        int joinedCases = joinedZeroFacts(program, template, registers);
        System.out.println("stack-value-mask=PASS cases=" + cases.size() * 4 + " wide-cases=" + wideCases + " checks=" + checks +
            " overlapping-cases=" + overlappingCases + " joined-cases=" + joinedCases +
            " evaluator=BigInteger raw-pcode=true target=ARM-LE");
        return checks;
    }

    private static int joinedZeroFacts(ProgramDB program, Instruction template, TargetRegisterMap registers)
            throws Exception {
        int cases = 0;
        for (int position = 0; position < 8; position++) {
            for (String shape : List.of("both-preserve", "first-corrupts", "second-corrupts")) {
                for (int merge : new int[] {PcodeOp.INT_OR, PcodeOp.INT_ADD}) {
                    for (boolean reversed : new boolean[] {false, true}) {
                        var code = new Code(program, template);
                        int offset = position * 8;
                        long selected = 0xffL << offset;
                        long firstMask = shape.equals("first-corrupts") ? selected : ~selected;
                        long secondMask = shape.equals("second-corrupts") ? selected : ~selected & 0x5555555555555555L;
                        var single = code.unique(1);
                        code.op(PcodeOp.SUBPIECE, single, code.source, code.constant(0, 4));
                        code.op(PcodeOp.INT_ZEXT, code.carrier, single);
                        code.op(PcodeOp.INT_LEFT, code.carrier, code.carrier, code.constant(offset, 4));
                        code.op(PcodeOp.INT_SEXT, code.nuisance, code.other);
                        code.op(PcodeOp.CBRANCH, null, code.constant(4, 4), code.condition);
                        code.op(PcodeOp.INT_AND, code.nuisance, code.nuisance, code.constant(firstMask, 8));
                        code.op(PcodeOp.BRANCH, null, code.constant(3, 4));
                        // Neither branch reaches this write. It must not contribute
                        // a false predecessor or kill the surviving carrier.
                        code.op(PcodeOp.COPY, code.carrier, code.constant(0, 8));
                        code.op(PcodeOp.INT_AND, code.nuisance, code.nuisance, code.constant(secondMask, 8));
                        code.op(merge, code.destination, reversed ? code.nuisance : code.carrier,
                            reversed ? code.carrier : code.nuisance);
                        code.op(PcodeOp.COPY, code.source, code.constant(0, 4));
                        String context = "join/position=" + position + "/shape=" + shape +
                            "/merge=" + merge + "/reversed=" + reversed;
                        require(IntraInstructionFlow.targets(code.instruction(), TaskMonitor.DUMMY) != null,
                            "invalid forward-only test instruction " + context);
                        var state = StackValueFlow.forIncomingPiece(program, new Varnode(code.source.getAddress(), 1));
                        require(state != null && state.advance(code.instruction(), false, TaskMonitor.DUMMY), context);
                        var location = state.location(registers);
                        boolean available = shape.equals("both-preserve");
                        require(location.available() == available, "join retained path-dependent byte " + context + ": " + location);
                        if (available) require(location instanceof RegisterStorage register &&
                            register.register().dwarfNumber() == 256 && register.valueBitOffset() == offset &&
                            register.bitSize() == 8, "wrong joined byte " + context + ": " + location);
                        for (boolean branch : new boolean[] {false, true}) {
                            boolean corrupts = shape.equals(branch ? "second-corrupts" : "first-corrupts");
                            boolean counterexample = false;
                            for (int value = 0; value <= 255; value++) {
                                for (long noise : NOISE) {
                                    BigInteger actual = evaluate(code, value, noise, 0, branch);
                                    BigInteger carried = BigInteger.valueOf(value).shiftLeft(offset);
                                    // A direct expression independently checks the interpreter's
                                    // branch targets and signed operand construction.
                                    BigInteger extra = BigInteger.valueOf((int) noise)
                                        .and(BigInteger.valueOf(branch ? secondMask : firstMask)).and(mask(64));
                                    BigInteger expected = (merge == PcodeOp.INT_OR ? carried.or(extra) : carried.add(extra)).and(mask(64));
                                    require(actual.equals(expected), "reference path execution differs " + context);
                                    int observed = actual.shiftRight(offset).and(BigInteger.valueOf(255)).intValue();
                                    if (!corrupts) require(observed == value, "preserving path changed byte " + context);
                                    else counterexample |= observed != value;
                                }
                            }
                            require(counterexample == corrupts, "path counterexample mismatch " + context + "/branch=" + branch);
                        }
                        cases++;
                    }
                }
            }
        }
        return cases;
    }

    private static int overlappingMerges(ProgramDB program, Instruction template, TargetRegisterMap registers)
            throws Exception {
        int cases = 0;
        for (int sourceByte = 0; sourceByte < 4; sourceByte++) {
            for (int shift : new int[] {0, 8, 16, 24, 32}) {
                for (int merge : new int[] {PcodeOp.INT_OR, PcodeOp.INT_ADD}) {
                    for (boolean reversed : new boolean[] {false, true}) {
                        var code = new Code(program, template);
                        // Both operands contain unknown bits outside the tracked byte.
                        // OR can preserve that byte even when the complete operands
                        // overlap. ADD can carry into it from their lower bytes.
                        code.op(PcodeOp.INT_ZEXT, code.carrier, code.source);
                        code.op(PcodeOp.INT_LEFT, code.carrier, code.carrier, code.constant(shift, 4));
                        code.op(PcodeOp.INT_ZEXT, code.nuisance, code.other);
                        code.op(PcodeOp.INT_AND, code.nuisance, code.nuisance,
                            code.constant(~(0xffL << (sourceByte * 8)), 8));
                        code.op(PcodeOp.INT_LEFT, code.nuisance, code.nuisance, code.constant(shift, 4));
                        code.op(merge, code.destination, reversed ? code.nuisance : code.carrier,
                            reversed ? code.carrier : code.nuisance);
                        code.op(PcodeOp.COPY, code.source, code.constant(0, 4));
                        var incoming = new Varnode(code.source.getAddress().add(sourceByte), 1);
                        var state = StackValueFlow.forIncomingPiece(program, incoming);
                        String context = "overlapping/source-byte=" + sourceByte + "/shift=" + shift +
                            "/merge=" + merge + "/reversed=" + reversed;
                        require(state != null && state.advance(code.instruction(), false, TaskMonitor.DUMMY), context);
                        var location = state.location(registers);
                        boolean available = merge == PcodeOp.INT_OR;
                        int offset = sourceByte * 8 + shift;
                        require(location.available() == available, "overlapping merge availability " + context + ": " + location);
                        if (available) require(location instanceof RegisterStorage register &&
                            register.register().dwarfNumber() == 256 && register.valueBitOffset() == offset &&
                            register.bitSize() == 8, "wrong merged byte " + context + ": " + location);
                        boolean counterexample = false;
                        for (int value = 0; value <= 255; value++) {
                            for (long noise : NOISE) {
                                int observed = evaluate(code, value, noise, sourceByte).shiftRight(offset)
                                    .and(BigInteger.valueOf(255)).intValue();
                                if (available || sourceByte == 0) require(observed == value,
                                    "byte expected unchanged was modified " + context);
                                else counterexample |= observed != value;
                            }
                        }
                        if (!available && sourceByte != 0) require(counterexample,
                            "carry rejection lacks a destructive example " + context);
                        // The least-significant-byte ADD is concretely safe, but the
                        // current disjoint-operand proof deliberately omits it. Do not
                        // mislabel that omission as evidence that its value changed.
                        cases++;
                    }
                }
            }
        }
        return cases;
    }

    private static int wideCarriers(ProgramDB program, Instruction template, TargetRegisterMap registers) throws Exception {
        int cases = 0;
        for (int width : new int[] {8, 9, 16, 32}) {
            for (int position : new java.util.LinkedHashSet<>(List.of(0, 7, width - 1))) {
                for (String shape : List.of("copy", "signed", "piece-high", "piece-low", "or-zero", "drop")) {
                    // Concatenation needs room for its extra high or low byte.
                    if ((shape.startsWith("piece") && position == width - 1) ||
                            shape.equals("piece-high") && position == 0) continue;
                    var code = new Code(program, template);
                    int initialWidth = shape.startsWith("piece") ? width - 1 : width;
                    var initial = code.unique(initialWidth);
                    int initialPosition = shape.equals("piece-high") ? position - 1 : position;
                    code.op(shape.equals("signed") ? PcodeOp.INT_SEXT : PcodeOp.INT_ZEXT, initial, code.source);
                    code.op(PcodeOp.INT_LEFT, initial, initial, code.constant(initialPosition * 8L, 4));
                    var carrier = code.unique(width);
                    if (shape.equals("piece-high")) code.op(PcodeOp.PIECE, carrier, initial, code.constant(0, 1));
                    else if (shape.equals("piece-low")) code.op(PcodeOp.PIECE, carrier, code.constant(0, 1), initial);
                    else code.op(PcodeOp.COPY, carrier, initial);
                    if (shape.equals("or-zero")) {
                        // Build a wide zero using a valid extension, not a >64-bit literal.
                        var zero = code.unique(width);
                        code.op(PcodeOp.INT_ZEXT, zero, code.constant(0, 1));
                        code.op(PcodeOp.INT_OR, carrier, carrier, zero);
                    }
                    int extraction = Math.min(position, width - 8);
                    if (shape.equals("drop")) {
                        // Shift the tracked byte completely out of its container.
                        code.op(PcodeOp.INT_LEFT, carrier, carrier, code.constant((width - position) * 8L, 4));
                    }
                    code.op(PcodeOp.SUBPIECE, code.destination, carrier, code.constant(extraction, 4));
                    code.op(PcodeOp.COPY, code.source, code.constant(0, 4));
                    var state = StackValueFlow.forIncomingPiece(program, new Varnode(code.source.getAddress(), 1));
                    String context = "wide=" + width + "/position=" + position + "/shape=" + shape;
                    require(state != null && state.advance(code.instruction(), false, TaskMonitor.DUMMY), context);
                    var location = state.location(registers);
                    boolean conservative = shape.equals("or-zero") && width > Long.BYTES;
                    boolean available = !shape.equals("drop") && !conservative;
                    require(location.available() == available, "wide availability " + context + ": " + location);
                    int offset = (position - extraction) * 8;
                    if (available) require(location instanceof RegisterStorage register &&
                        register.register().dwarfNumber() == 256 && register.valueBitOffset() == offset &&
                        register.bitSize() == 8, "wide surviving byte " + context + ": " + location);
                    boolean counterexample = false;
                    for (int value = 0; value <= 255; value++) {
                        for (long noise : NOISE) {
                            int observed = evaluate(code, value, noise).shiftRight(offset).and(BigInteger.valueOf(255)).intValue();
                            if (!shape.equals("drop")) require(observed == value, "wide concrete value changed " + context);
                            else counterexample |= observed != value;
                        }
                    }
                    if (shape.equals("drop")) require(counterexample, "wide drop has no destructive example " + context);
                    // A wide OR is deliberately outside the long-sized zero-mask proof.
                    // Its concrete identity above is not permission to invent a location.
                    cases++;
                }
            }
        }
        return cases;
    }

    private static final class Code {
        final ProgramDB program;
        final Instruction template;
        final List<PcodeOp> operations = new ArrayList<>();
        final Varnode source, other, condition, destination, carrier, nuisance;
        long next = 0x1000;

        Code(ProgramDB program, Instruction template) {
            this.program = program;
            this.template = template;
            source = new Varnode(program.getRegister("r3").getAddress(), 4);
            other = new Varnode(program.getRegister("r0").getAddress(), 4);
            condition = new Varnode(program.getRegister("r2").getAddress(), 1);
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
        return evaluate(code, value, noise, 0);
    }

    private static BigInteger evaluate(Code code, int value, long noise, int sourceByte) {
        return evaluate(code, value, noise, sourceByte, false);
    }

    private static BigInteger evaluate(Code code, int value, long noise, int sourceByte, boolean branch) {
        Map<Varnode, BigInteger> values = new HashMap<>();
        BigInteger selected = BigInteger.valueOf(255).shiftLeft(sourceByte * 8);
        values.put(code.source, BigInteger.valueOf(noise).and(mask(32).xor(selected))
            .or(BigInteger.valueOf(value).shiftLeft(sourceByte * 8)));
        values.put(code.other, BigInteger.valueOf(noise));
        values.put(code.condition, branch ? BigInteger.ONE : BigInteger.ZERO);
        for (int index = 0; index < code.operations.size(); index++) {
            PcodeOp op = code.operations.get(index);
            if (op.getOpcode() == PcodeOp.BRANCH || op.getOpcode() == PcodeOp.CBRANCH) {
                if (op.getOpcode() == PcodeOp.BRANCH || read(values, op.getInput(1)).signum() != 0) {
                    int distance = Math.toIntExact(op.getInput(0).getOffset());
                    if (distance <= 0 || distance > code.operations.size() - index) {
                        throw new AssertionError("reference interpreter requires bounded forward branches");
                    }
                    index += distance - 1;
                }
                continue;
            }
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
                case PcodeOp.PIECE -> first.shiftLeft(op.getInput(1).getSize() * 8).or(second);
                case PcodeOp.SUBPIECE -> first.shiftRight(second.intValueExact() * 8);
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
