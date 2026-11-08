package ghidradwarfforge.calls;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BooleanSupplier;

import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.AddressNormalizer;
import ghidradwarfforge.elf.ElfCodeBytes;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.elf.ElfRelocationEffects;
import ghidradwarfforge.targets.UnwindAbiProfile;

/**
 * Bounded original-image switch targets, separate from function ownership and
 * call/tail classification. Computed-reference hints are never target evidence.
 */
public final class GhidraBoundedSwitch {
    public record TableRead(long address, int bytes, long value) { }
    public record Proof(Address guardStart, Address guardBranch, Address transfer,
            int maximumIndex, List<Address> targets, List<TableRead> reads) {
        public Proof { targets = List.copyOf(targets); reads = List.copyOf(reads); }
    }
    private record Cell(int space, long offset, int bytes) { }
    private sealed interface Term permits Input, Literal, Expression, Unknown { int bytes(); }
    private record Input(Cell cell) implements Term { public int bytes() { return cell.bytes(); } }
    private record Literal(long value, int bytes) implements Term { }
    private record Expression(int opcode, int bytes, List<Term> inputs) implements Term { }
    private record Unknown(int bytes) implements Term { }
    private record Bound(Input input, int maximum) { }
    private GhidraBoundedSwitch() { }

    /**
     * The candidate begins at an unsigned comparison followed by a conditional
     * branch. Success proves the bounded fallthrough transfer only. A caller
     * must still validate graph closure and ownership before claiming all calls.
     */
    public static Proof prove(Program program, Instruction compare, ElfImage image, long delta,
            TaskMonitor monitor) throws IOException, CancelledException {
        monitor.checkCancelled();
        var owner = program.getFunctionManager().getFunctionContaining(compare.getAddress());
        require(owner != null, "switch guard has no owning function");
        var profile = UnwindAbiProfile.selectForCallSites(program, owner, image, delta, monitor);
        BooleanSupplier cancelled = monitor::isCancelled;
        var effects = ElfRelocationEffects.inspect(image, cancelled);
        try (var original = ElfCodeBytes.open(image, cancelled)) {
            var first = operations(program, compare, image, delta, profile, original, effects, monitor);
            require(compare.getPrototype().getFlowType(compare.getInstructionContext()).isFallthrough(), "comparison does not fall through");
            var branch = following(program, compare);
            exclusiveEntry(program, compare, branch, monitor);
            var second = operations(program, branch, image, delta, profile, original, effects, monitor);
            require(branch.getDefaultFallThrough() != null &&
                branch.getPrototype().getFlowType(branch.getInstructionContext()).isConditional() && branch.getPrototype().getFlowType(branch.getInstructionContext()).isJump(),
                "guard is not a conditional jump");
            require(second.length > 0 && second[second.length - 1].getOpcode() == PcodeOp.CBRANCH,
                "guard lacks a final conditional branch");
            require(second[second.length - 1].getNumInputs() == 2 &&
                second[second.length - 1].getInput(0).isAddress() &&
                second[second.length - 1].getInput(0).getOffset() !=
                    AddressNormalizer.toElfAddress(branch.getDefaultFallThrough().getOffset(), delta),
                "guard taken edge enters its bounded fallthrough");
            var state = new LinkedHashMap<Cell, Term>();
            for (var operation : first) { monitor.checkCancelled(); symbolic(operation, state); }
            state.keySet().removeIf(cell -> cell.space() == program.getAddressFactory().getUniqueSpace().getSpaceID());
            for (int i = 0; i < second.length - 1; i++) { monitor.checkCancelled(); symbolic(second[i], state); }
            var condition = symbolicRead(second[second.length - 1].getInput(1), state);
            // The bounded path is the conditional branch's fallthrough.
            require(condition instanceof Expression e && e.opcode() == PcodeOp.BOOL_NEGATE,
                "guard does not establish a bounded fallthrough");
            var bound = bound(((Expression) condition).inputs().getFirst());
            require(bound != null, "unsigned finite guard bound is unavailable");
            for (var op : first) {
                monitor.checkCancelled();
                require(op.getOutput() == null || !overlap(cell(op.getOutput()), bound.input().cell()), "comparison changes its index");
            }
            for (var op : second) {
                monitor.checkCancelled();
                require(op.getOutput() == null || !overlap(cell(op.getOutput()), bound.input().cell()), "guard changes its index");
            }

            var window = new ArrayList<PcodeOp[]>();
            Instruction previous = branch;
            Instruction transfer = null;
            for (int count = 0; count < 32; count++) {
                monitor.checkCancelled();
                var next = following(program, previous);
                exclusiveEntry(program, previous, next, monitor);
                var ops = operations(program, next, image, delta, profile, original, effects, monitor);
                window.add(ops);
                if (next.getPrototype().getFlowType(next.getInstructionContext()).isComputed() && next.getPrototype().getFlowType(next.getInstructionContext()).isJump() &&
                        !next.getPrototype().getFlowType(next.getInstructionContext()).hasFallthrough()) {
                    require(ops.length > 0 && ops[ops.length - 1].getOpcode() == PcodeOp.BRANCHIND,
                        "computed transfer lacks final indirect branch");
                    transfer = next;
                    break;
                }
                require(next.getPrototype().getFlowType(next.getInstructionContext()).isFallthrough(), "nonlinear switch dispatch window");
                previous = next;
            }
            require(transfer != null, "switch dispatch window exceeds budget");
            var targets = new ArrayList<Address>();
            var reads = new LinkedHashMap<Long, TableRead>();
            for (int index = 0; index <= bound.maximum(); index++) {
                monitor.checkCancelled();
                var values = new LinkedHashMap<Cell, Long>();
                values.put(bound.input().cell(), (long) index);
                Long target = null;
                for (var ops : window) {
                    values.keySet().removeIf(c -> c.space() == program.getAddressFactory().getUniqueSpace().getSpaceID());
                    for (var op : ops) {
                        monitor.checkCancelled();
                        int opcode = op.getOpcode();
                        require(pure(opcode) || opcode == PcodeOp.LOAD || opcode == PcodeOp.BRANCHIND,
                            "dispatch has unmodeled p-code side effects");
                        if (opcode == PcodeOp.BRANCHIND) {
                            require(target == null && op == ops[ops.length - 1] && ops == window.getLast(),
                                "multiple dispatch transfers");
                            target = numericRead(op.getInput(0), values);
                            require(target != null && target >= 0, "computed target is not a proven address");
                            continue;
                        }
                        require(op.getOutput() != null && (op.getOutput().isRegister() || op.getOutput().isUnique()),
                            "dispatch has unmodeled side effects");
                        Long value;
                        if (opcode == PcodeOp.LOAD) {
                            require(op.getInput(0).isConstant() && op.getInput(0).getOffset() ==
                                program.getAddressFactory().getDefaultAddressSpace().getSpaceID(), "nondefault table space");
                            Long address = numericRead(op.getInput(1), values);
                            require(address != null, "table address depends on unbounded state");
                            value = readTable(original, effects, address, op.getOutput().getSize(), reads, monitor);
                        }
                        else value = numeric(op, values);
                        numericWrite(values, cell(op.getOutput()), value);
                    }
                }
                require(target != null, "missing computed target");
                Address address = program.getAddressFactory().getDefaultAddressSpace().getAddress(Math.addExact(target, delta));
                var instruction = program.getListing().getInstructionAt(address);
                require(instruction != null, "switch target lacks a decoded instruction boundary");
                operations(program, instruction, image, delta, profile, original, effects, monitor);
                targets.add(address);
            }
            monitor.checkCancelled();
            return new Proof(compare.getAddress(), branch.getAddress(), transfer.getAddress(), bound.maximum(),
                targets, new ArrayList<>(reads.values()));
        }
    }

    private static PcodeOp[] operations(Program program, Instruction instruction, ElfImage image, long delta,
            UnwindAbiProfile.Bound profile, ElfCodeBytes original, ElfRelocationEffects effects,
            TaskMonitor monitor) throws IOException, CancelledException {
        monitor.checkCancelled();
        profile.requireInstruction(instruction, monitor);
        require(!instruction.isLengthOverridden() && !instruction.isFallThroughOverridden() &&
            instruction.getFlowOverride() == ghidra.program.model.listing.FlowOverride.NONE &&
            !instruction.isInDelaySlot() && instruction.getDelaySlotDepth() == 0 &&
            !instruction.getPrototype().hasNext2Dependency(), "unsupported switch instruction override/context");
        try {
            byte[] bytes = instruction.getParsedBytes();
            byte[] live = new byte[bytes.length];
            require(program.getMemory().getBytes(instruction.getAddress(), live) == bytes.length && Arrays.equals(bytes, live),
                "switch instruction bytes changed");
            long address = AddressNormalizer.toElfAddress(instruction.getAddress().getOffset(), delta);
            effects.requireUnchanged(address, bytes.length, monitor::isCancelled);
            original.requireMatches(address, bytes, monitor::isCancelled);
            var normalized = instruction.getAddress().getAddressSpace().getAddress(address);
            var buffer = new ByteMemBufferImpl(normalized, bytes, program.getLanguage().isBigEndian());
            var pseudo = new PseudoInstruction(program.getAddressFactory(), normalized, instruction.getPrototype(), buffer, instruction);
            var result = pseudo.getPcode(false);
            require(result != null && result.length <= 4096, "unbounded normalized instruction semantics");
            return result;
        }
        catch (ghidra.program.model.mem.MemoryAccessException | ghidra.program.model.address.AddressOverflowException invalid) {
            throw new IllegalArgumentException("switch instruction could not be normalized", invalid);
        }
    }

    private static Instruction following(Program program, Instruction previous) {
        var address = previous.getDefaultFallThrough();
        require(address != null && address.equals(previous.getMaxAddress().next()), "nonsequential dispatch fallthrough");
        var next = program.getListing().getInstructionAt(address);
        require(next != null, "undecoded dispatch instruction");
        return next;
    }

    private static void exclusiveEntry(Program program, Instruction previous, Instruction next, TaskMonitor monitor)
            throws CancelledException {
        require(program.getFunctionManager().getFunctionAt(next.getAddress()) == null, "dispatch has another function entry");
        var destinations = program.getReferenceManager().getReferenceDestinationIterator(
            new AddressSet(next.getAddress(), next.getMaxAddress()), true);
        int references = 0;
        while (destinations.hasNext()) {
            monitor.checkCancelled();
            for (var ref : program.getReferenceManager().getReferencesTo(destinations.next())) {
                monitor.checkCancelled();
                require(++references <= 65_536, "switch incoming-reference budget exceeded");
                require(!ref.isEntryPointReference(), "dispatch has another entry marker");
                if (ref.getReferenceType().isFlow()) require(ref.getFromAddress().equals(previous.getAddress()) &&
                    ref.getToAddress().equals(next.getAddress()), "dispatch has an incoming edge bypassing its guard");
            }
        }
    }

    private static long readTable(ElfCodeBytes original, ElfRelocationEffects effects,
            long address, int bytes, Map<Long, TableRead> reads, TaskMonitor monitor) throws IOException, CancelledException {
        monitor.checkCancelled();
        require(reads.size() < 4096, "table read budget exceeded");
        effects.requireUnchanged(address, bytes, monitor::isCancelled);
        byte[] data = original.readReadOnlyData(address, bytes, monitor::isCancelled);
        long value = 0;
        for (int i = 0; i < bytes; i++) value |= (data[i] & 255L) << (8 * i);
        var read = new TableRead(address, bytes, value);
        var old = reads.put(address, read);
        require(old == null || old.equals(read), "inconsistent switch table read");
        return value;
    }

    private static Cell cell(Varnode node) {
        require(node.getSize() >= 1 && node.getSize() <= 8, "unsupported switch scalar width");
        require(node.getOffset() >= 0 && node.getOffset() <= Long.MAX_VALUE - node.getSize(), "switch scalar span overflows");
        return new Cell(node.getAddress().getAddressSpace().getSpaceID(), node.getOffset(), node.getSize());
    }
    private static boolean overlap(Cell a, Cell b) {
        return a.space() == b.space() && a.offset() < b.offset() + b.bytes() && b.offset() < a.offset() + a.bytes();
    }
    private static long mask(long value, int bytes) { return bytes == 8 ? value : value & ((1L << (bytes * 8)) - 1); }
    private static Term symbolicRead(Varnode node, Map<Cell, Term> state) {
        require(node.getSize() >= 1 && node.getSize() <= 8, "unsupported guard scalar width");
        if (node.isConstant()) return new Literal(mask(node.getOffset(), node.getSize()), node.getSize());
        var key = cell(node);
        return state.computeIfAbsent(key, ignored -> node.isRegister() ? new Input(key) : new Unknown(node.getSize()));
    }
    private static void symbolic(PcodeOp op, Map<Cell, Term> state) {
        require(pure(op.getOpcode()), "guard has unmodeled p-code effects");
        require(op.getOutput() != null && (op.getOutput().isRegister() || op.getOutput().isUnique()), "guard has control or memory side effects");
        var inputs = Arrays.stream(op.getInputs()).map(n -> symbolicRead(n, state)).toList();
        int bytes = op.getOutput().getSize();
        Term value = op.getOpcode() == PcodeOp.COPY ? inputs.getFirst() :
            new Expression(op.getOpcode(), bytes, inputs);
        Cell output = cell(op.getOutput());
        // Retain explicit unknowns for aliases, never resurrect a pre-write input.
        state.replaceAll((key, old) -> overlap(key, output) ? new Unknown(key.bytes()) : old);
        state.put(output, value);
    }
    private static Bound bound(Term term) {
        if (!(term instanceof Expression expr)) return null;
        if (expr.opcode() == PcodeOp.BOOL_OR && expr.inputs().size() == 2) {
            var a = expr.inputs().get(0); var b = expr.inputs().get(1);
            Bound less = less(a); Term equal = b;
            if (less == null) { less = less(b); equal = a; }
            if (less != null && equalsBoundary(equal, less.input(), less.maximum() + 1)) {
                return new Bound(less.input(), less.maximum() + 1);
            }
        }
        return less(term);
    }
    private static Bound less(Term term) {
        if (!(term instanceof Expression e) || e.opcode() != PcodeOp.INT_LESS || e.inputs().size() != 2 ||
                !(e.inputs().get(0) instanceof Input input) || !(e.inputs().get(1) instanceof Literal limit) ||
                input.bytes() != limit.bytes() || limit.value() < 1 || limit.value() > 255) return null;
        return new Bound(input, (int) limit.value() - 1);
    }
    private static boolean equalsBoundary(Term term, Input input, int limit) {
        if (!(term instanceof Expression e) || e.opcode() != PcodeOp.INT_EQUAL || e.inputs().size() != 2) return false;
        var a = e.inputs().get(0); var b = e.inputs().get(1);
        if (a.equals(input) && b.equals(new Literal(limit, input.bytes()))) return true;
        return a instanceof Expression sub && sub.opcode() == PcodeOp.INT_SUB && sub.bytes() == input.bytes() &&
            sub.inputs().equals(List.of(input, new Literal(limit, input.bytes()))) && b.equals(new Literal(0, input.bytes()));
    }
    private static Long numericRead(Varnode node, Map<Cell, Long> values) {
        require(node.getSize() >= 1 && node.getSize() <= 8, "unsupported dispatch scalar width");
        if (node.isConstant()) return mask(node.getOffset(), node.getSize());
        if (!node.isRegister() && !node.isUnique()) return null;
        var key = cell(node);
        for (var entry : values.entrySet()) {
            var owner = entry.getKey();
            if (owner.space() == key.space() && owner.offset() <= key.offset() &&
                    key.offset() - owner.offset() <= owner.bytes() - key.bytes()) {
                return mask(entry.getValue() >>> (8 * (key.offset() - owner.offset())), key.bytes());
            }
        }
        return null;
    }
    private static void numericWrite(Map<Cell, Long> state, Cell output, Long value) {
        state.keySet().removeIf(key -> overlap(key, output));
        if (value != null) state.put(output, mask(value, output.bytes()));
    }
    private static Long numeric(PcodeOp op, Map<Cell, Long> values) {
        Long a = op.getNumInputs() > 0 ? numericRead(op.getInput(0), values) : null;
        Long b = op.getNumInputs() > 1 ? numericRead(op.getInput(1), values) : null;
        if (a == null) return null;
        int opcode = op.getOpcode();
        if (opcode == PcodeOp.COPY || opcode == PcodeOp.INT_ZEXT) return a;
        if (opcode == PcodeOp.INT_SEXT) { int shift = 64 - 8 * op.getInput(0).getSize(); return (a << shift) >> shift; }
        if (b == null) return null;
        return switch (opcode) {
            case PcodeOp.INT_ADD -> a + b;
            case PcodeOp.INT_SUB -> a - b;
            case PcodeOp.INT_MULT -> a * b;
            case PcodeOp.INT_AND -> a & b;
            case PcodeOp.INT_OR -> a | b;
            case PcodeOp.INT_XOR -> a ^ b;
            case PcodeOp.INT_LEFT -> Long.compareUnsigned(b, 64) < 0 ? a << b : 0L;
            case PcodeOp.INT_RIGHT -> Long.compareUnsigned(b, 64) < 0 ? a >>> b : 0L;
            default -> null;
        };
    }
    private static boolean pure(int opcode) {
        return switch (opcode) {
            case PcodeOp.COPY, PcodeOp.INT_EQUAL, PcodeOp.INT_NOTEQUAL, PcodeOp.INT_SLESS,
                PcodeOp.INT_SLESSEQUAL, PcodeOp.INT_LESS, PcodeOp.INT_LESSEQUAL, PcodeOp.INT_ZEXT,
                PcodeOp.INT_SEXT, PcodeOp.INT_ADD, PcodeOp.INT_SUB, PcodeOp.INT_CARRY, PcodeOp.INT_SCARRY,
                PcodeOp.INT_SBORROW, PcodeOp.INT_2COMP, PcodeOp.INT_NEGATE, PcodeOp.INT_XOR,
                PcodeOp.INT_AND, PcodeOp.INT_OR, PcodeOp.INT_LEFT, PcodeOp.INT_RIGHT, PcodeOp.INT_SRIGHT,
                PcodeOp.INT_MULT, PcodeOp.BOOL_NEGATE, PcodeOp.BOOL_XOR, PcodeOp.BOOL_AND,
                PcodeOp.BOOL_OR, PcodeOp.SUBPIECE, PcodeOp.PIECE, PcodeOp.POPCOUNT, PcodeOp.LZCOUNT -> true;
            default -> false;
        };
    }
    private static void require(boolean condition, String reason) {
        if (!condition) throw new IllegalArgumentException(reason);
    }
}
