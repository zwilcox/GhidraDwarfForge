package ghidradwarfforge.calls;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.calls.GhidraCallSiteEvidence.*;
import ghidradwarfforge.calls.CallValue.*;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.targets.UnwindAbiProfile;
import ghidradwarfforge.unwind.UnwindFlow.Bank;
import ghidradwarfforge.unwind.UnwindFlow.Cell;

/**
 * Register actual-value analysis over captured integer instructions. Memory
 * reads and unproved calls forget values; no ABI preservation is assumed.
 * Consumers must still match parameter storage/types and admitted call sites.
 */
public final class GhidraCallArgumentFlow {
    public record State(Map<Cell, CallValue> values) {
        public State {
            if (values.size() > 1024) throw new IllegalArgumentException("call-value state budget exceeded");
            values = Collections.unmodifiableMap(new LinkedHashMap<>(values));
        }
    }
    public record Result(Map<Address, State> transfers, Map<Address, String> omissions) {
        public Result {
            transfers = Collections.unmodifiableMap(new LinkedHashMap<>(transfers));
            omissions = Collections.unmodifiableMap(new LinkedHashMap<>(omissions));
        }
    }
    private record Execution(State after, State transfer) { }
    private static final State EMPTY = new State(Map.of());
    private GhidraCallArgumentFlow() { }

    /** Caller maintains the same consistent Program/input view as the supplied boundary proof. */
    public static Result analyze(Program program, GhidraTailStateProof.Result proof, ElfImage image, long delta,
            TaskMonitor monitor) throws CancelledException {
        var transfers = new LinkedHashMap<Address, State>();
        var omissions = new LinkedHashMap<Address, String>();
        var admitted = new LinkedHashSet<Address>();
        for (var tail : proof.tails()) admitted.add(tail.instruction());
        for (var function : proof.captures()) {
            monitor.checkCancelled();
            try {
                require(function.captureComplete(), "incomplete instruction inventory");
                require(!proof.omissions().containsKey(function.function().entry()), "unproved tail boundary or entry contract");
                transfers.putAll(analyzeFunction(program, function, admitted, image, delta, monitor));
            }
            catch (IllegalArgumentException unavailable) { omissions.put(function.function().entry(), unavailable.getMessage()); }
        }
        return new Result(transfers, omissions);
    }

    private static Map<Address, State> analyzeFunction(Program program, FunctionEvidence capture,
            Set<Address> admitted, ElfImage image, long delta, TaskMonitor monitor) throws CancelledException {
        var function = program.getFunctionManager().getFunctionAt(capture.function().entry());
        require(function != null, "caller disappeared");
        var profile = UnwindAbiProfile.selectForCallSites(program, function, image, delta, monitor);
        var nodes = new LinkedHashMap<Address, InstructionEvidence>();
        var edges = new LinkedHashMap<Address, List<Address>>();
        var addressComputations = new LinkedHashSet<Address>();
        for (var instruction : capture.instructions()) {
            monitor.checkCancelled();
            var nativeInstruction = program.getListing().getInstructionAt(instruction.address());
            require(nativeInstruction != null, "captured instruction disappeared");
            profile.requireInstruction(nativeInstruction, monitor);
            var kind = instruction.transfer().kind();
            require(kind != Kind.UNAVAILABLE, "unavailable instruction semantics");
            if (kind == Kind.DIRECT_TAIL_CANDIDATE || kind == Kind.INDIRECT_TAIL_CANDIDATE || kind == Kind.THUNK_TRANSFER) {
                require(admitted.contains(instruction.address()), "external branch lacks a boundary proof");
            }
            // Address-derived literals in Ghidra's p-code may have been rebased.
            // Do not serialize them as integer constants or silently treat them
            // as original ELF pointers. Parameter pointer provenance is separate.
            for (var reference : nativeInstruction.getReferencesFrom()) {
                if (reference.isMemoryReference() && !reference.getReferenceType().isFlow()) {
                    addressComputations.add(instruction.address());
                }
            }
            var successors = new ArrayList<Address>();
            if (instruction.fallThrough() != null) successors.add(instruction.fallThrough());
            if (kind == Kind.INTERNAL_BRANCH && !successors.contains(instruction.transfer().target())) successors.add(instruction.transfer().target());
            nodes.put(instruction.address(), instruction);
            edges.put(instruction.address(), successors);
        }
        var entry = new LinkedHashMap<Cell, CallValue>();
        for (var register : profile.registers().entrySet()) {
            if (!register.getValue().equals(profile.stackPointer()) && !register.getValue().equals(profile.programCounter()) &&
                    register.getKey() != profile.description().returnNumber()) {
                entry.put(register.getValue(), new Incoming(register.getKey(), register.getValue().bytes()));
            }
        }
        // On stack-return profiles returnNumber may be the PC rather than an
        // argument register; the explicit exclusions above retain that distinction.
        var before = new LinkedHashMap<Address, State>();
        before.put(capture.function().entry(), new State(entry));
        var pending = new ArrayDeque<Address>(); pending.add(capture.function().entry());
        int steps = 0;
        while (!pending.isEmpty()) {
            monitor.checkCancelled();
            require(++steps <= 1_000_000, "call-value fixed-point budget exceeded");
            Address address = pending.removeFirst();
            var instruction = nodes.get(address);
            require(instruction != null, "unresolved graph edge");
            State after = execute(instruction, before.get(address), profile.permittedCells(),
                addressComputations.contains(address), monitor).after();
            for (Address successor : edges.get(address)) {
                monitor.checkCancelled();
                State old = before.get(successor);
                State next = old == null ? after : merge(old, after, null);
                if (!next.equals(old)) { before.put(successor, next); pending.addLast(successor); }
            }
        }
        var result = new LinkedHashMap<Address, State>();
        for (var instruction : capture.instructions()) {
            monitor.checkCancelled();
            State state = before.get(instruction.address());
            if (state == null) continue;
            var execution = execute(instruction, state, profile.permittedCells(),
                addressComputations.contains(instruction.address()), monitor);
            Kind kind = instruction.transfer().kind();
            if (execution.transfer() != null && (kind == Kind.DIRECT_CALL || kind == Kind.INDIRECT_CALL || admitted.contains(instruction.address()))) {
                result.put(instruction.address(), execution.transfer());
            }
        }
        return result;
    }

    private static Execution execute(InstructionEvidence instruction, State state, List<Cell> registers,
            boolean addressComputation, TaskMonitor monitor) throws CancelledException {
        var values = new LinkedHashMap<>(state.values());
        values.keySet().removeIf(cell -> cell.bank() == Bank.TEMPORARY);
        return execute(instruction, 0, new State(values), registers, addressComputation, new int[] {0}, 0, monitor);
    }

    private static Execution execute(InstructionEvidence instruction, int index, State input, List<Cell> registers,
            boolean addressComputation, int[] steps, int depth, TaskMonitor monitor) throws CancelledException {
        require(depth <= 32, "intra-instruction branch depth exceeded");
        var values = new LinkedHashMap<>(input.values());
        var operations = instruction.operations();
        for (int cursor = index; cursor < operations.size(); cursor++) {
            monitor.checkCancelled();
            require(++steps[0] <= 16_384, "intra-instruction value budget exceeded");
            Operation operation = operations.get(cursor);
            int opcode = operation.opcode();
            if (opcode == PcodeOp.CALL || opcode == PcodeOp.CALLIND) {
                return new Execution(EMPTY, registersOnly(values));
            }
            if (opcode == PcodeOp.RETURN) return new Execution(registersOnly(values), null);
            if (opcode == PcodeOp.BRANCH || opcode == PcodeOp.CBRANCH) {
                var target = operation.inputs().getFirst().address();
                boolean micro = target.isConstantAddress() || (instruction.transfer().kind() == Kind.ORDINARY &&
                    target.equals(instruction.end().next()));
                if (!micro) return new Execution(registersOnly(values), registersOnly(values));
                long displacement = target.isConstantAddress() ? target.getOffset() : operations.size() - cursor;
                require(displacement > 0 && displacement <= operations.size() - cursor, "unbounded intra-instruction branch");
                int destination = cursor + (int) displacement;
                Execution taken = execute(instruction, destination, new State(values), registers, addressComputation, steps, depth + 1, monitor);
                if (opcode == PcodeOp.BRANCH) return taken;
                CallValue condition = read(values, operation.inputs().get(1));
                Execution notTaken = execute(instruction, cursor + 1, new State(values), registers, addressComputation, steps, depth + 1, monitor);
                require(taken.transfer() == null && notTaken.transfer() == null, "conditional microcode contains machine transfer");
                return new Execution(merge(taken.after(), notTaken.after(), condition), null);
            }
            if (opcode == PcodeOp.STORE) continue; // Memory values are never recovered by this analysis.
            require(opcode != PcodeOp.CALLOTHER && opcode != PcodeOp.UNIMPLEMENTED && opcode != PcodeOp.INDIRECT &&
                opcode != PcodeOp.BRANCHIND, "unmodeled side effect");
            if (operation.output() == null) throw new IllegalArgumentException("unmodeled output-free p-code");
            if (operation.output().address().isMemoryAddress()) continue; // Direct memory store.
            Cell output = cell(operation.output());
            CallValue value = null;
            if (!addressComputation) {
                try { value = value(operation, values); }
                catch (IllegalArgumentException unavailable) { /* Forget an expression that exceeds its budget/width. */ }
            }
            write(values, output, value, registers);
        }
        return new Execution(registersOnly(values), null);
    }

    private static CallValue value(Operation operation, Map<Cell, CallValue> state) {
        int opcode = operation.opcode(), bytes = operation.output().bytes();
        CallValue a = operation.inputs().isEmpty() ? null : read(state, operation.inputs().getFirst());
        CallValue b = operation.inputs().size() < 2 ? null : read(state, operation.inputs().get(1));
        if (a == null) return null;
        if (opcode == PcodeOp.COPY) return a.bytes() == bytes ? a : null;
        if (opcode == PcodeOp.INT_ZEXT || opcode == PcodeOp.INT_SEXT) return CallValue.extend(a, opcode == PcodeOp.INT_SEXT, bytes);
        if (opcode == PcodeOp.BOOL_NEGATE) return CallValue.binary(Op.EQUAL, a, new Literal(0, a.bytes()), 1);
        if (opcode == PcodeOp.INT_NEGATE) return CallValue.binary(Op.XOR, a, new Literal(-1, a.bytes()), bytes);
        if (b == null) return null;
        if (opcode == PcodeOp.SUBPIECE) {
            if (!(b instanceof Literal offset) || Long.compareUnsigned(offset.value(), 8) >= 0) return null;
            return CallValue.slice(a, (int) offset.value() * 8, bytes);
        }
        Op op = switch (opcode) {
            case PcodeOp.INT_ADD -> Op.ADD;
            case PcodeOp.INT_SUB -> Op.SUBTRACT;
            case PcodeOp.INT_MULT -> Op.MULTIPLY;
            case PcodeOp.INT_AND, PcodeOp.BOOL_AND -> Op.AND;
            case PcodeOp.INT_OR, PcodeOp.BOOL_OR -> Op.OR;
            case PcodeOp.INT_XOR, PcodeOp.BOOL_XOR -> Op.XOR;
            case PcodeOp.INT_LEFT -> Op.SHIFT_LEFT;
            case PcodeOp.INT_RIGHT -> Op.SHIFT_RIGHT;
            case PcodeOp.INT_EQUAL -> Op.EQUAL;
            case PcodeOp.INT_NOTEQUAL -> Op.NOT_EQUAL;
            default -> null;
        };
        if ((op == Op.SHIFT_LEFT || op == Op.SHIFT_RIGHT) && !(b instanceof Literal)) return null;
        return op == null ? null : CallValue.binary(op, a, b, bytes);
    }

    private static State registersOnly(Map<Cell, CallValue> values) {
        var registers = new LinkedHashMap<>(values);
        registers.keySet().removeIf(cell -> cell.bank() == Bank.TEMPORARY);
        return new State(registers);
    }
    private static Cell cell(Operand operand) {
        require(operand.address().isRegisterAddress() || operand.address().isUniqueAddress(), "unsupported value space");
        return new Cell(operand.address().isRegisterAddress() ? Bank.REGISTER : Bank.TEMPORARY,
            operand.address().getOffset(), operand.bytes());
    }
    private static CallValue read(Map<Cell, CallValue> values, Operand operand) {
        if (operand.address().isConstantAddress()) return new Literal(operand.address().getOffset(), operand.bytes());
        if (!operand.address().isRegisterAddress() && !operand.address().isUniqueAddress()) return null;
        return read(values, cell(operand));
    }
    /** The selected ABI profiles are little endian; no generic big-endian register layout claim. */
    public static CallValue read(Map<Cell, CallValue> values, Cell cell) {
        for (var entry : values.entrySet()) {
            Cell owner = entry.getKey();
            if (owner.bank() == cell.bank() && owner.offset() <= cell.offset() &&
                    cell.offset() - owner.offset() <= owner.bytes() - cell.bytes()) {
                try { return CallValue.slice(entry.getValue(), (int) (cell.offset() - owner.offset()) * 8, cell.bytes()); }
                catch (IllegalArgumentException unavailable) { return null; }
            }
        }
        return null;
    }
    private static boolean overlaps(Cell left, Cell right) {
        return left.bank() == right.bank() && left.offset() < right.offset() + right.bytes() && right.offset() < left.offset() + left.bytes();
    }
    private static void write(Map<Cell, CallValue> values, Cell output, CallValue value, List<Cell> registers) {
        Cell destination = output;
        if (value != null && output.bank() == Bank.REGISTER) {
            for (Cell register : registers) {
                if (register.bank() == output.bank() && register.offset() <= output.offset() &&
                        output.offset() - register.offset() <= register.bytes() - output.bytes()) {
                    CallValue old = read(values, register);
                    if (old != null && !register.equals(output)) {
                        try {
                            int shift = (int) (output.offset() - register.offset()) * 8;
                            long mask = (output.bytes() == 8 ? -1L : (1L << (output.bytes() * 8)) - 1) << shift;
                            var retained = CallValue.binary(Op.AND, old, new Literal(~mask, register.bytes()), register.bytes());
                            var inserted = CallValue.binary(Op.SHIFT_LEFT, CallValue.extend(value, false, register.bytes()), new Literal(shift, 1), register.bytes());
                            value = CallValue.binary(Op.OR, retained, inserted, register.bytes());
                            destination = register;
                        }
                        catch (IllegalArgumentException unavailable) { /* Keep only the independently known written slice. */ }
                    }
                    break;
                }
            }
        }
        Cell replaced = destination;
        values.keySet().removeIf(existing -> overlaps(existing, replaced));
        if (value != null) values.put(destination, value);
    }
    private static State merge(State yes, State no, CallValue condition) {
        var candidates = new LinkedHashSet<Cell>(); candidates.addAll(yes.values().keySet()); candidates.addAll(no.values().keySet());
        var ordered = candidates.stream().sorted(Comparator.comparingInt(Cell::bytes).reversed()).toList();
        var values = new LinkedHashMap<Cell, CallValue>();
        for (Cell cell : ordered) {
            if (values.keySet().stream().anyMatch(existing -> overlaps(existing, cell))) continue;
            CallValue a = read(yes.values(), cell), b = read(no.values(), cell);
            if (a == null || b == null) continue;
            try {
                if (a.equals(b)) values.put(cell, a);
                else if (condition != null) values.put(cell, CallValue.select(condition, a, b));
            }
            catch (IllegalArgumentException unavailable) { /* Neither excessive expressions nor partial path facts survive. */ }
        }
        return new State(values);
    }
    private static void require(boolean value, String reason) { if (!value) throw new IllegalArgumentException(reason); }
}
