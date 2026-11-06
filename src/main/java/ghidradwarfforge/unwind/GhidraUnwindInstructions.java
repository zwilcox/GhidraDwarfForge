package ghidradwarfforge.unwind;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.unwind.UnwindFlow.*;

/** Native listing capture; it supplies no ABI entry state or implicit call proof. */
public final class GhidraUnwindInstructions {
    @FunctionalInterface
    public interface CallProof {
        /** Null means the call effects are unknown, not the ordinary ABI. */
        Call resolve(Instruction instruction) throws CancelledException;
    }
    public record Observation(String bytes, String assembly, String context,
            List<String> pcode, List<String> omissions) {
        public Observation { pcode = List.copyOf(pcode); omissions = List.copyOf(omissions); }
    }
    public record Captured(Map<Address, Node<Address>> graph, Map<Address, Observation> observations) { }

    private GhidraUnwindInstructions() { }

    public static Captured capture(Program program, Function function, CallProof calls, TaskMonitor monitor)
            throws CancelledException {
        Objects.requireNonNull(calls);
        monitor.checkCancelled();
        var body = new AddressSet(function.getBody());
        if (function.isExternal() || function.isThunk() || body.isEmpty() || body.getNumAddresses() > 1_048_576) {
            throw new IllegalArgumentException("unsupported or unbounded unwind function body");
        }
        var graph = new LinkedHashMap<Address, Node<Address>>();
        var evidence = new LinkedHashMap<Address, Observation>();
        var covered = new AddressSet();
        var instructions = program.getListing().getInstructions(body, true);
        while (instructions.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = instructions.next();
            Address address = instruction.getAddress();
            if (!address.getAddressSpace().equals(program.getAddressFactory().getDefaultAddressSpace()) ||
                    !body.contains(address, instruction.getMaxAddress()) || instruction.isLengthOverridden() ||
                    instruction.getLength() != instruction.getParsedLength() ||
                    instruction.getFlowOverride() != FlowOverride.NONE || instruction.isFallThroughOverridden() ||
                    instruction.isInDelaySlot() || instruction.getDelaySlotDepth() != 0) {
                throw new IllegalArgumentException("incomplete, overridden or unsupported instruction at " + address);
            }
            byte[] bytes;
            try {
                bytes = instruction.getParsedBytes();
                byte[] live = new byte[bytes.length];
                if (bytes.length != instruction.getLength() || program.getMemory().getBytes(address, live) != live.length ||
                        !Arrays.equals(bytes, live)) throw new IllegalArgumentException("instruction bytes changed at " + address);
            }
            catch (ghidra.program.model.mem.MemoryAccessException failure) {
                throw new IllegalArgumentException("unreadable instruction at " + address, failure);
            }
            var flow = instruction.getFlowType();
            var successors = new LinkedHashSet<Address>();
            if (flow.hasFallthrough()) {
                Address next = instruction.getFallThrough();
                if (next == null || !next.equals(instruction.getMaxAddress().next())) {
                    throw new IllegalArgumentException("unproved fallthrough at " + address);
                }
                successors.add(next);
            }
            if (!flow.isCall()) successors.addAll(List.of(instruction.getFlows()));
            if (flow.isComputed() && !flow.isCall() && !flow.isTerminal()) {
                throw new IllegalArgumentException("unresolved control flow at " + address);
            }
            if (!Arrays.equals(instruction.getFlows(), instruction.getDefaultFlows())) {
                throw new IllegalArgumentException("flow targets differ from decode at " + address);
            }
            var effects = new ArrayList<Effect>();
            var omissions = new ArrayList<String>();
            var pcode = new ArrayList<String>();
            PcodeOp[] operations = instruction.getPcode();
            if (operations == null || operations.length > 4096 || (operations.length == 0 && !flow.isFallthrough())) {
                effects.add(new Opaque("missing or unbounded p-code"));
                omissions.add("missing or unbounded p-code");
            }
            else {
                for (PcodeOp operation : operations) {
                    monitor.checkCancelled();
                    pcode.add(operation.toString());
                    try {
                        lower(program, instruction, operation, calls, effects);
                    }
                    catch (IllegalArgumentException unsupported) {
                        omissions.add(unsupported.getMessage());
                    }
                }
                if (flow.isCall() && Arrays.stream(operations).filter(operation ->
                        operation.getOpcode() == PcodeOp.CALL || operation.getOpcode() == PcodeOp.CALLIND).count() != 1) {
                    omissions.add("call flow has no unique raw p-code call; special call semantics are unproved");
                }
                // A later understood operation must not recreate selected facts
                // after an unknown instruction-level effect.
                if (!omissions.isEmpty()) effects = new ArrayList<>(List.of(new Opaque(String.join("; ", omissions))));
            }
            var contextRegister = program.getProgramContext().getBaseContextRegister();
            var context = contextRegister == null ? null : instruction.getRegisterValue(contextRegister);
            graph.put(address, new Node<>(effects, List.copyOf(successors)));
            evidence.put(address, new Observation(HexFormat.of().formatHex(bytes), instruction.toString(),
                String.valueOf(context), pcode, omissions));
            covered.add(address, instruction.getMaxAddress());
            if (graph.size() > 65_536) throw new IllegalArgumentException("unwind instruction budget exceeded");
        }
        if (!covered.equals(body) || !graph.containsKey(function.getEntryPoint())) {
            throw new IllegalArgumentException("function contains partial or undecoded instruction bytes");
        }
        for (var node : graph.values()) {
            monitor.checkCancelled();
            if (!graph.keySet().containsAll(node.successors())) {
                throw new IllegalArgumentException("function edge crosses a body gap or leaves the proved graph");
            }
        }
        if (!body.equals(function.getBody())) throw new IllegalArgumentException("function body changed during capture");
        monitor.checkCancelled();
        return new Captured(Collections.unmodifiableMap(graph), Collections.unmodifiableMap(evidence));
    }

    private static void lower(Program program, Instruction instruction, PcodeOp op,
            CallProof calls, List<Effect> effects) throws CancelledException {
        int opcode = op.getOpcode();
        switch (opcode) {
            case PcodeOp.COPY -> effects.add(new Copy(cell(op.getOutput()), operand(op.getInput(0))));
            case PcodeOp.INT_ADD, PcodeOp.INT_SUB -> effects.add(new Add(cell(op.getOutput()),
                operand(op.getInput(0)), operand(op.getInput(1)), opcode == PcodeOp.INT_SUB));
            case PcodeOp.LOAD -> {
                requireMemorySpace(program, op);
                effects.add(new Load(cell(op.getOutput()), operand(op.getInput(1))));
            }
            case PcodeOp.STORE -> {
                requireMemorySpace(program, op);
                effects.add(new Store(operand(op.getInput(1)), operand(op.getInput(2)), op.getInput(2).getSize()));
            }
            case PcodeOp.CALL, PcodeOp.CALLIND -> {
                if (!instruction.getFlowType().isCall()) throw new IllegalArgumentException("p-code call contradicts instruction flow");
                Call proof = calls.resolve(instruction);
                if (proof == null) throw new IllegalArgumentException("call has no separately proved effects");
                effects.add(proof);
            }
            case PcodeOp.BRANCH, PcodeOp.CBRANCH -> {
                Varnode target = op.getInput(0);
                if (target.isConstant() || !Set.of(instruction.getFlows()).contains(target.getAddress())) {
                    throw new IllegalArgumentException("unmodeled intra-instruction branch");
                }
            }
            case PcodeOp.RETURN -> {
                if (!instruction.getFlowType().isTerminal()) throw new IllegalArgumentException("unproved return flow");
            }
            case PcodeOp.CALLOTHER, PcodeOp.UNIMPLEMENTED, PcodeOp.BRANCHIND, PcodeOp.INDIRECT ->
                throw new IllegalArgumentException("unmodeled side effects: " + op.getMnemonic());
            default -> {
                // These raw operations have only their explicit output effect.
                // Killing that physical span is safe; deriving a saved identity
                // from a cast, slice, arithmetic or predicate needs another proof.
                if (op.getOutput() == null || !pure(opcode)) {
                    throw new IllegalArgumentException("unmodeled operation: " + op.getMnemonic());
                }
                effects.add(new Kill(cell(op.getOutput())));
            }
        }
    }

    private static boolean pure(int opcode) {
        return switch (opcode) {
            case PcodeOp.INT_EQUAL, PcodeOp.INT_NOTEQUAL, PcodeOp.INT_SLESS, PcodeOp.INT_SLESSEQUAL,
                PcodeOp.INT_LESS, PcodeOp.INT_LESSEQUAL, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT,
                PcodeOp.INT_CARRY, PcodeOp.INT_SCARRY, PcodeOp.INT_SBORROW, PcodeOp.INT_2COMP,
                PcodeOp.INT_NEGATE, PcodeOp.INT_XOR, PcodeOp.INT_AND, PcodeOp.INT_OR,
                PcodeOp.INT_LEFT, PcodeOp.INT_RIGHT, PcodeOp.INT_SRIGHT, PcodeOp.INT_MULT,
                PcodeOp.INT_DIV, PcodeOp.INT_SDIV, PcodeOp.INT_REM, PcodeOp.INT_SREM,
                PcodeOp.BOOL_NEGATE, PcodeOp.BOOL_XOR, PcodeOp.BOOL_AND, PcodeOp.BOOL_OR,
                PcodeOp.PIECE, PcodeOp.SUBPIECE, PcodeOp.POPCOUNT, PcodeOp.LZCOUNT -> true;
            default -> false;
        };
    }

    private static void requireMemorySpace(Program program, PcodeOp operation) {
        if (!operation.getInput(0).isConstant() || operation.getInput(0).getOffset() !=
                program.getAddressFactory().getDefaultAddressSpace().getSpaceID()) {
            throw new IllegalArgumentException("non-default memory space");
        }
    }
    public static Cell cell(Varnode node) {
        if (node == null || (!node.isRegister() && !node.isUnique())) {
            throw new IllegalArgumentException("non-register/non-temporary physical cell");
        }
        return new Cell(node.isRegister() ? Bank.REGISTER : Bank.TEMPORARY, node.getOffset(), node.getSize());
    }
    private static Operand operand(Varnode node) {
        return node.isConstant() ? new Constant(node.getOffset(), node.getSize()) : cell(node);
    }
}
