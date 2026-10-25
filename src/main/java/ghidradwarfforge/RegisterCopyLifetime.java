package ghidradwarfforge;

import java.util.List;
import java.util.Map;

import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.RegisterStorage;

/**
 * One exact low-bit register backup in proven straight-line code. A separately
 * decoded direct leaf call requires both an ABI contract and no register writes.
 * Facts describe the entry value's bits, not a register's whole numeric value.
 * No memory facts, unique temporaries, chains, or lost-fact reacquisition.
 */
final class RegisterCopyLifetime {
    record Backup(long end, RegisterStorage storage) {
    }

    private RegisterCopyLifetime() {
    }

    static Backup prove(Program program, long start, long end,
            List<Instruction> instructions, Varnode incoming, int bytes,
            TargetRegisterMap registers, TaskMonitor monitor) throws CancelledException {
        return prove(program, start, end, instructions, incoming, bytes, registers, Map.of(), monitor);
    }

    static Backup prove(Program program, long start, long end,
            List<Instruction> instructions, Varnode incoming, int bytes,
            TargetRegisterMap registers,
            Map<ghidra.program.model.address.Address, DirectLeafCalls.Leaf> calls,
            TaskMonitor monitor) throws CancelledException {
        Register original = exactLowRegister(program, incoming);
        if (original == null || bytes <= 0 || incoming.getSize() != bytes) {
            return null;
        }
        Register originalBase = original.getBaseRegister();
        long handoff = GhidraVariableStorage.registerPrefixEnd(start, end, instructions,
            originalBase, calls, monitor);
        if (handoff <= start || handoff >= end) {
            return null;
        }
        var codeSpace = instructions.get(0).getAddress().getAddressSpace();
        Register candidate = null;
        RegisterStorage mapped = null;
        boolean selected = false;
        boolean originalAlive = true;
        long candidateEnd = end;
        for (Instruction instruction : instructions) {
            monitor.checkCancelled();
            // Length overrides can separate the listing boundary from the real
            // machine instruction. This added proof never uses such boundaries.
            if (instruction.isLengthOverridden() || instruction.isFallThroughOverridden() ||
                    !instruction.getAddress().getAddressSpace().equals(codeSpace) ||
                    !instruction.getMaxAddress().getAddressSpace().equals(codeSpace) ||
                    (instruction.getFallThrough() != null &&
                        !instruction.getFallThrough().getAddressSpace().equals(codeSpace)) ||
                    instruction.getFlowType().isConditional() ||
                    instruction.getFlowType().isJump() || instruction.getFlowType().isOverride()) {
                return null;
            }
            long next = Math.addExact(instruction.getMaxAddress().getOffset(), 1);
            boolean writesOriginal = GhidraVariableStorage.writesRegister(instruction,
                originalBase);
            boolean mayAcquire = !selected && originalAlive && !writesOriginal;
            boolean attempted = false;
            PcodeOp[] operations = instruction.getPcode();
            for (int index = 0; index < operations.length; index++) {
                monitor.checkCancelled();
                PcodeOp operation = operations[index];
                if (operation.getOpcode() == PcodeOp.CALL && candidate != null &&
                        !calls.get(instruction.getAddress()).preserves(candidate, monitor)) {
                    candidate = null;
                }
                if (!validCopyShape(operation)) {
                    return null;
                }
                if (operation.getOpcode() == PcodeOp.RETURN &&
                        (index != operations.length - 1 || operation.getOutput() != null ||
                            operation.getNumInputs() != 1 || operation.getInput(0) == null ||
                            operation.getInput(0).getSize() !=
                                instruction.getAddress().getAddressSpace().getPointerSize())) {
                    return null;
                }
                Varnode output = operation.getOutput();
                Register destination = exactLowRegister(program, output);
                Register source = copySource(program, operation, bytes);
                // A listing-only original-register effect has no raw ordering.
                // Do not source any backup write from an instruction that also
                // writes the original, even if a candidate already existed.
                boolean fromOriginal = originalAlive && !writesOriginal &&
                    sameBase(source, original);
                boolean fromCandidate = sameBase(source, candidate);
                boolean keepsCandidate = destination != null &&
                    sameBase(destination, candidate) && (fromOriginal || fromCandidate);
                boolean createsCandidate = mayAcquire && !attempted && candidate == null &&
                    fromOriginal && destination != null &&
                    !sameBase(destination, original);

                // Read the old input fact before invalidating the output. This
                // admits a narrow COPY then same-base widening in one instruction,
                // but COPY followed by any unproved partial write loses the fact.
                if (GhidraVariableStorage.unprovenStore(program, operation)) {
                    return null;
                }
                if (overlaps(output, originalBase)) {
                    originalAlive = false;
                }
                if (candidate != null && overlaps(output, candidate.getBaseRegister())) {
                    candidate = keepsCandidate ? destination : null;
                }
                if (createsCandidate) {
                    attempted = true;
                    var location = GhidraVariableStorage.mappedRegister(destination, bytes,
                        registers, "copied parameter");
                    if (location instanceof RegisterStorage register) {
                        candidate = destination;
                        mapped = register;
                    }
                }
            }
            // Listing result objects can describe effects omitted from raw
            // outputs. Every overlapping result must have explicit p-code byte
            // coverage; those ordered writes have already updated the fact.
            if (candidate != null && !resultsCovered(instruction, candidate.getBaseRegister(),
                    monitor)) {
                candidate = null;
            }
            if (writesOriginal) {
                originalAlive = false;
            }
            if (selected && candidate == null && candidateEnd == end) {
                candidateEnd = next;
            }
            if (!selected && candidate != null) {
                // Publish only the completed instruction's state. The original
                // kill instruction is never allowed to establish a new backup.
                selected = true;
            }
        }
        // A backup killed before the handoff gives no additional interval.
        return selected && candidateEnd > handoff ? new Backup(candidateEnd, mapped) : null;
    }

    private static Register copySource(Program program, PcodeOp operation, int bytes) {
        if ((operation.getOpcode() != PcodeOp.COPY &&
                operation.getOpcode() != PcodeOp.INT_ZEXT) ||
                operation.getNumInputs() != 1 || operation.getInput(0) == null ||
                operation.getOutput() == null || operation.getInput(0).getSize() != bytes) {
            return null;
        }
        int outputSize = operation.getOutput().getSize();
        if (operation.getOpcode() == PcodeOp.COPY ? outputSize != bytes : outputSize <= bytes) {
            return null;
        }
        return exactLowRegister(program, operation.getInput(0));
    }

    private static boolean validCopyShape(PcodeOp operation) {
        if (operation.getOpcode() != PcodeOp.COPY &&
                operation.getOpcode() != PcodeOp.INT_ZEXT) {
            return true;
        }
        if (operation.getNumInputs() != 1 || operation.getInput(0) == null ||
                operation.getOutput() == null || operation.getInput(0).getSize() <= 0 ||
                operation.getOutput().getSize() <= 0) {
            return false;
        }
        int input = operation.getInput(0).getSize();
        int output = operation.getOutput().getSize();
        return operation.getOpcode() == PcodeOp.COPY ? input == output : input < output;
    }

    private static Register exactLowRegister(Program program, Varnode varnode) {
        if (varnode == null || !varnode.isRegister() || varnode.getSize() <= 0) {
            return null;
        }
        Register register = program.getRegister(varnode);
        // Ghidra's size map also returns containing registers for smaller
        // unnamed varnodes. Non-null lookup alone does not identify this slice.
        if (register == null || !register.getAddress().equals(varnode.getAddress()) ||
                register.getBitLength() != (long) varnode.getSize() * 8 ||
                register.getLeastSignificantBitInBaseRegister() != 0) {
            return null;
        }
        return register;
    }

    private static boolean sameBase(Register first, Register second) {
        return first != null && second != null &&
            first.getBaseRegister().equals(second.getBaseRegister());
    }


    private static boolean overlaps(Varnode output, Register base) {
        return output != null && output.isRegister() &&
            output.getAddress().getAddressSpace().equals(base.getAddress().getAddressSpace()) &&
            output.getOffset() < Math.addExact(base.getAddress().getOffset(), base.getMinimumByteSize()) &&
            Math.addExact(output.getOffset(), (long) output.getSize()) > base.getAddress().getOffset();
    }

    private static boolean resultsCovered(Instruction instruction, Register base,
            TaskMonitor monitor) throws CancelledException {
        for (Object result : instruction.getResultObjects()) {
            monitor.checkCancelled();
            if (!(result instanceof Register register) ||
                    !register.getAddress().getAddressSpace().equals(
                        base.getAddress().getAddressSpace())) {
                continue;
            }
            // Physical overlap also catches result registers outside the
            // named parent tree (or aliases supplied by a language adapter).
            long offset = Math.max(register.getAddress().getOffset(), base.getAddress().getOffset());
            long end = Math.min(Math.addExact(register.getAddress().getOffset(), register.getMinimumByteSize()),
                Math.addExact(base.getAddress().getOffset(), base.getMinimumByteSize()));
            while (offset < end) {
                long covered = offset;
                for (PcodeOp operation : instruction.getPcode()) {
                    Varnode output = operation.getOutput();
                    if (output != null && output.isRegister() &&
                            output.getAddress().getAddressSpace().equals(
                                register.getAddress().getAddressSpace()) &&
                            output.getOffset() <= offset) {
                        covered = Math.max(covered,
                            Math.addExact(output.getOffset(), (long) output.getSize()));
                    }
                }
                if (covered <= offset) {
                    return false;
                }
                offset = covered;
            }
        }
        return true;
    }
}
