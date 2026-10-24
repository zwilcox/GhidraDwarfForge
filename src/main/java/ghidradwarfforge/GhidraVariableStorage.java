package ghidradwarfforge;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import ghidra.app.cmd.function.CallDepthChangeInfo;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.CompositeStorage;
import ghidradwarfforge.locations.VariableStorageModel.OmissionReason;
import ghidradwarfforge.locations.VariableStorageModel.Piece;
import ghidradwarfforge.locations.VariableStorageModel.RegisterStorage;
import ghidradwarfforge.locations.VariableStorageModel.StackStorage;
import ghidradwarfforge.locations.VariableStorageModel.Storage;
import ghidradwarfforge.locations.VariableStorageModel.UnavailableStorage;

/** Evidence-constrained translation of Ghidra listing variable storage. */
public final class GhidraVariableStorage {
    public record StackDepthInterval(long start, long end, int depth, boolean known) {
        public StackDepthInterval {
            if (start < 0 || end <= start) {
                throw new IllegalArgumentException("invalid stack-depth interval");
            }
        }
    }

    public record StackDepthProfile(String registerName,
            List<StackDepthInterval> intervals) {
        public StackDepthProfile {
            if (registerName == null || intervals == null) {
                throw new IllegalArgumentException("invalid stack-depth profile");
            }
            intervals = List.copyOf(intervals);
        }
    }

    public record StorageInterval(long start, long end, Storage storage) {
        public StorageInterval {
            if (start < 0 || end <= start || storage == null) {
                throw new IllegalArgumentException("invalid Ghidra storage interval");
            }
        }
    }

    private GhidraVariableStorage() {
    }

    /**
     * Returns a stable register location only when the parameter has one simple
     * mapped register and no instruction can overwrite or call-clobber it.
     */
    public static Storage stableParameter(Program program, Function function,
            Parameter parameter, TargetRegisterMap registers, TaskMonitor monitor)
            throws CancelledException {
        VariableStorage storage = parameter.getVariableStorage();
        if (!parameter.hasAssignedStorage() || storage == null ||
                storage.isUnassignedStorage()) {
            return unavailable(OmissionReason.UNASSIGNED,
                "Ghidra parameter has no assigned storage");
        }
        if (!storage.isValid() || storage.isBadStorage() || storage.isForcedIndirect()) {
            return unavailable(OmissionReason.UNSUPPORTED_STORAGE,
                "parameter storage is invalid, indirect, or unsupported");
        }
        if (storage.getVarnodeCount() > 1) {
            return stableComposite(program, function, storage, parameter.getLength(),
                registers, monitor, "parameter");
        }
        if (storage.isStackStorage()) {
            return stackStorage(storage, parameter.getLength(), "parameter");
        }
        if (!storage.isRegisterStorage()) {
            return unavailable(OmissionReason.UNSUPPORTED_STORAGE,
                "parameter is neither one direct register nor one stack slot");
        }
        return stableRegister(program, function, parameter.getRegister(),
            parameter.getLength(), registers, monitor, "parameter");
    }

    /**
     * Refines only an otherwise rejected simple register parameter. The value
     * exists at the first writing instruction (before it executes), and becomes
     * unavailable at its fall-through address unless a separate ordered p-code
     * proof establishes one completed register backup before that instruction.
     * An empty result leaves the original conservative rejection unchanged.
     */
    public static List<StorageInterval> parameterPrefix(Program program, Function function,
            Parameter parameter, TargetRegisterMap registers, Storage rejected,
            TaskMonitor monitor) throws CancelledException {
        if (!(rejected instanceof UnavailableStorage unavailable) ||
                unavailable.reason() != OmissionReason.REGISTER_MODIFIED ||
                parameter.getVariableStorage().getVarnodeCount() != 1 ||
                !parameter.getVariableStorage().isRegisterStorage()) {
            return List.of();
        }
        Register register = parameter.getRegister();
        if (register == null || function.getBody().getNumAddressRanges() != 1 ||
                !function.getEntryPoint().equals(function.getBody().getMinAddress())) {
            return List.of();
        }
        Storage mapped = mappedRegister(register, parameter.getLength(), registers, "parameter");
        if (!mapped.available()) {
            return List.of();
        }
        List<Instruction> instructions = new ArrayList<>();
        var instructionsByAddress = new HashMap<ghidra.program.model.address.Address, Instruction>();
        var iterator = program.getListing().getInstructions(function.getBody(), true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = iterator.next();
            for (PcodeOp operation : instruction.getPcode()) {
                monitor.checkCancelled();
                if (unprovenStore(program, operation)) {
                    return List.of();
                }
            }
            instructions.add(instruction);
            instructionsByAddress.put(instruction.getAddress(), instruction);
        }
        // A second entry can target an offcut byte inside a listed instruction,
        // not just an instruction start. Inspect every referenced destination.
        var destinations = program.getReferenceManager()
            .getReferenceDestinationIterator(function.getBody(), true);
        while (destinations.hasNext()) {
            monitor.checkCancelled();
            var destination = destinations.next();
            if (destination.equals(function.getEntryPoint())) {
                continue;
            }
            var references = program.getReferenceManager().getReferencesTo(destination);
            while (references.hasNext()) {
                monitor.checkCancelled();
                var reference = references.next();
                var type = reference.getReferenceType();
                if (type.isFlow()) {
                    Instruction predecessor = instructionsByAddress.get(reference.getFromAddress());
                    boolean ordinaryFallthrough = type == ghidra.program.model.symbol.RefType.FALL_THROUGH &&
                        predecessor != null && instructionsByAddress.containsKey(destination) &&
                        destination.equals(predecessor.getFallThrough()) &&
                        destination.equals(predecessor.getMaxAddress().next());
                    if (!ordinaryFallthrough) {
                        return List.of();
                    }
                }
            }
        }
        long start = function.getEntryPoint().getOffset();
        long end = Math.addExact(function.getBody().getMaxAddress().getOffset(), 1);
        long boundary = registerPrefixEnd(start, end, instructions, register.getBaseRegister(),
            monitor);
        if (boundary <= start) {
            return List.of();
        }
        List<StorageInterval> result = new ArrayList<>();
        result.add(new StorageInterval(start, boundary, mapped));
        var formalType = parameter.getFormalDataType();
        var storage = parameter.getVariableStorage();
        // A storage-width copy is not evidence for a differently sized formal
        // value. Keep the established prefix when this narrower proof fails.
        RegisterCopyLifetime.Backup backup = formalType != null &&
                formalType.getLength() == parameter.getLength() &&
                storage.size() == parameter.getLength()
            ? RegisterCopyLifetime.prove(program, start, end, instructions,
                storage.getFirstVarnode(), parameter.getLength(), registers, monitor)
            : null;
        if (backup != null) {
            result.add(new StorageInterval(boundary, backup.end(), backup.storage()));
            boundary = backup.end();
        }
        if (boundary < end) {
            result.add(new StorageInterval(boundary, end, unavailable(
                OmissionReason.REGISTER_MODIFIED,
                "proven parameter register storage was overwritten before address 0x" +
                    Long.toHexString(boundary) + "; later storage is not established")));
        }
        return List.copyOf(result);
    }

    /** Exact fully decoded, ordinary straight-line leaf proof; -1 rejects it. */
    static long registerPrefixEnd(long start, long end, List<Instruction> instructions,
            Register register, TaskMonitor monitor) throws CancelledException {
        long expected = start;
        long firstWriteEnd = -1;
        boolean returned = false;
        for (Instruction instruction : instructions) {
            monitor.checkCancelled();
            if (returned || instruction.getAddress().getOffset() != expected ||
                    instruction.isInDelaySlot() || instruction.getDelaySlotDepth() != 0 ||
                    instruction.getFlowOverride() != FlowOverride.NONE) {
                return -1;
            }
            long next = Math.addExact(instruction.getMaxAddress().getOffset(), 1);
            if (next <= expected || next > end) {
                return -1;
            }
            boolean returns = false;
            for (PcodeOp operation : instruction.getPcode()) {
                switch (operation.getOpcode()) {
                    case PcodeOp.BRANCH, PcodeOp.CBRANCH, PcodeOp.BRANCHIND,
                        PcodeOp.CALL, PcodeOp.CALLIND, PcodeOp.CALLOTHER,
                        PcodeOp.UNIMPLEMENTED -> { return -1; }
                    case PcodeOp.RETURN -> returns = true;
                    default -> { }
                }
            }
            var flow = instruction.getFlowType();
            if (returns) {
                if (!flow.isTerminal() || flow.isCall() || next != end ||
                        instruction.getFallThrough() != null) {
                    return -1;
                }
                returned = true;
            }
            else if (!flow.isFallthrough() || instruction.getFallThrough() == null ||
                    instruction.getFallThrough().getOffset() != next) {
                return -1;
            }
            if (firstWriteEnd == -1 && writesRegister(instruction, register)) {
                firstWriteEnd = next;
            }
            expected = next;
        }
        return returned && expected == end ? firstWriteEnd : -1;
    }

    /** Returns one exact stack or provably stable register local. */
    public static Storage stableLocal(Program program, Function function,
            Variable variable, TargetRegisterMap registers, TaskMonitor monitor)
            throws CancelledException {
        VariableStorage storage = variable.getVariableStorage();
        if (!variable.hasAssignedStorage() || storage == null ||
                storage.isUnassignedStorage()) {
            return unavailable(OmissionReason.UNASSIGNED,
                "Ghidra local has no assigned storage");
        }
        if (!storage.isValid() || storage.isBadStorage() || storage.isForcedIndirect()) {
            return unavailable(OmissionReason.UNSUPPORTED_STORAGE,
                "local storage is invalid, indirect, or unsupported");
        }
        if (storage.getVarnodeCount() > 1) {
            if (variable.getFirstUseOffset() != 0) {
                return unavailable(OmissionReason.UNKNOWN_LIFETIME,
                    "composite local does not become live at function entry");
            }
            return stableComposite(program, function, storage, variable.getLength(),
                registers, monitor, "local");
        }
        if (storage.isStackStorage()) {
            if (variable.getFirstUseOffset() != 0) {
                // Pinned Ghidra stack symbols do not model first-use ranges.
                // Keep the declaration, without inventing a start or an end.
                return unavailable(OmissionReason.UNKNOWN_LIFETIME,
                    "stack local has unsupported nonzero first-use offset " +
                        variable.getFirstUseOffset() + "; its lifetime is not established");
            }
            return stackStorage(storage, variable.getLength(), "local");
        }
        if (!storage.isRegisterStorage()) {
            return unavailable(OmissionReason.UNSUPPORTED_STORAGE,
                "local is neither one direct register nor one stack slot");
        }
        if (variable.getFirstUseOffset() != 0) {
            return unavailable(OmissionReason.UNKNOWN_LIFETIME,
                "register local does not become live at function entry");
        }
        return stableRegister(program, function, variable.getRegister(),
            variable.getLength(), registers, monitor, "local");
    }

    private static Storage stableRegister(Program program, Function function,
            Register register, int byteSize, TargetRegisterMap registers,
            TaskMonitor monitor, String description) throws CancelledException {
        Storage mapped = mappedRegister(register, byteSize, registers, description);
        if (!mapped.available()) {
            return mapped;
        }
        Register base = register.getBaseRegister();
        Instruction opaqueInstruction = null;
        InstructionIterator instructions = program.getListing()
            .getInstructions(function.getBody(), true);
        while (instructions.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = instructions.next();
            if (instruction.getFlowType().isCall()) {
                return unavailable(OmissionReason.CALL_CLOBBERED,
                    "function contains a call that may clobber " + description +
                        " register " + base.getName());
            }
            if (writesRegister(instruction, base)) {
                return unavailable(OmissionReason.REGISTER_MODIFIED,
                    "function writes " + description + " register " + base.getName() +
                        " at " + instruction.getAddress());
            }
            if (opaqueInstruction == null && hasOpaqueRegisterEffects(program, instruction)) {
                opaqueInstruction = instruction;
            }
        }
        // Retain the existing call/modeled-write diagnostic precedence even
        // when an earlier instruction also has opaque effects.
        if (opaqueInstruction != null) {
            return unavailable(OmissionReason.UNKNOWN_LIFETIME,
                "opaque instruction effects prevent proving the " + description +
                    " register " + base.getName() + " stable at " +
                    opaqueInstruction.getAddress());
        }
        return mapped;
    }

    private static boolean hasOpaqueRegisterEffects(Program program, Instruction instruction) {
        PcodeOp[] operations = instruction.getPcode();
        boolean opaque = false;
        for (PcodeOp operation : operations) {
            if (operation.getOpcode() == PcodeOp.UNIMPLEMENTED || unprovenStore(program, operation)) {
                return true;
            }
            if (operation.getOpcode() == PcodeOp.CALLOTHER) {
                opaque = true;
                // A user operation may change registers beyond its explicit
                // output (Ghidra's USERDEFINED p-code contract). Its selector
                // must still be present even for the terminal-boundary case.
                if (operation.getNumInputs() == 0 || operation.getInput(0) == null ||
                        !operation.getInput(0).isConstant()) {
                    return true;
                }
            }
        }
        return opaque && !ordinaryTerminalReturn(instruction, operations);
    }

    static boolean unprovenStore(Program program, PcodeOp operation) {
        if (operation.getOpcode() != PcodeOp.STORE) {
            return false;
        }
        if (operation.getNumInputs() != 3 || operation.getOutput() != null ||
                operation.getInput(0) == null || operation.getInput(1) == null ||
                operation.getInput(2) == null || !operation.getInput(0).isConstant() ||
                operation.getInput(2).getSize() <= 0) {
            return true;
        }
        long id = operation.getInput(0).getOffset();
        if (id != (int) id && id != Integer.toUnsignedLong((int) id)) {
            return true;
        }
        var space = program.getAddressFactory().getAddressSpace((int) id);
        // STORE's destination selector is an address-space ID, not an address.
        // Only a well-formed store into known memory can leave register facts
        // intact. It never establishes a memory location for the parameter.
        return space == null || !space.isMemorySpace() ||
            operation.getInput(1).getSize() != space.getPointerSize();
    }


    private static boolean ordinaryTerminalReturn(Instruction instruction,
            PcodeOp[] operations) {
        var flow = instruction.getFlowType();
        if (instruction.getFlowOverride() != FlowOverride.NONE ||
                instruction.isInDelaySlot() || instruction.getDelaySlotDepth() != 0 ||
                !flow.isTerminal() || flow.isCall() || flow.isConditional() ||
                flow.isJump() || flow.isOverride() || flow.hasFallthrough() ||
                instruction.getFallThrough() != null || operations.length == 0) {
            return false;
        }
        PcodeOp last = operations[operations.length - 1];
        if (last.getOpcode() != PcodeOp.RETURN || last.getOutput() != null ||
                last.getNumInputs() != 1 || last.getInput(0) == null ||
                last.getInput(0).getSize() !=
                    instruction.getAddress().getAddressSpace().getPointerSize()) {
            return false;
        }
        for (int index = 0; index < operations.length - 1; index++) {
            switch (operations[index].getOpcode()) {
                case PcodeOp.BRANCH, PcodeOp.CBRANCH, PcodeOp.BRANCHIND,
                    PcodeOp.CALL, PcodeOp.CALLIND, PcodeOp.RETURN -> { return false; }
                default -> { }
            }
        }
        // Locations describe the state before a machine instruction executes.
        // An ordinary unconditional return ends this invocation; no later instruction
        // observes the user operation's effects in this function. This is a
        // control-flow boundary, not a purity claim or a userop-name whitelist.
        return true;
    }

    static Storage mappedRegister(Register register, int byteSize,
            TargetRegisterMap registers, String description) {
        if (register == null) {
            return unavailable(OmissionReason.UNSUPPORTED_STORAGE,
                "Ghidra did not resolve the " + description + " register");
        }
        Register base = register.getBaseRegister();
        long requiredBits = Math.multiplyExact((long) byteSize, 8L);
        if (requiredBits <= 0 || requiredBits > register.getBitLength() ||
                requiredBits > Integer.MAX_VALUE) {
            return unavailable(OmissionReason.UNSUPPORTED_STORAGE,
                description + " size does not fit its Ghidra register");
        }
        // The physical base may be a wider, unmapped vector or paired register.
        // Describe the value through a mapped logical register that contains it;
        // write detection still checks the entire base alias in the caller.
        for (Register candidate = register; candidate != null;
                candidate = candidate.getParentRegister()) {
            if (registers.dwarfNumbers().containsKey(candidate.getName())) {
                int offset = Math.subtractExact(register.getLeastSignificantBitInBaseRegister(),
                    candidate.getLeastSignificantBitInBaseRegister());
                if (offset < 0 || Math.addExact((long) offset, requiredBits) >
                        candidate.getBitLength()) {
                    return unavailable(OmissionReason.UNSUPPORTED_STORAGE,
                        description + " does not fit its mapped enclosing register");
                }
                return registers.register(candidate.getName(), offset,
                    Math.toIntExact(requiredBits));
            }
        }
        return registers.register(base.getName(),
            register.getLeastSignificantBitInBaseRegister(), Math.toIntExact(requiredBits));
    }

    private static Storage stableComposite(Program program, Function function,
            VariableStorage storage, int byteSize, TargetRegisterMap registers,
            TaskMonitor monitor, String description) throws CancelledException {
        if (storage.size() != byteSize) {
            return unavailable(OmissionReason.UNSUPPORTED_STORAGE,
                description + " composite storage does not exactly match its size");
        }
        List<Piece> pieces = new ArrayList<>();
        // Ghidra orders these varnodes in memory order: LSB first for LE and MSB
        // first for BE, exactly the order required by a DWARF composite location.
        for (Varnode varnode : storage.getVarnodes()) {
            if (!varnode.isRegister()) {
                return unavailable(OmissionReason.UNSUPPORTED_STORAGE,
                    description + " composite contains a non-register piece");
            }
            Storage piece = stableRegister(program, function, program.getRegister(varnode),
                varnode.getSize(), registers, monitor, description + " piece");
            if (!(piece instanceof RegisterStorage register)) {
                return piece;
            }
            pieces.add(new Piece(register, Math.multiplyExact(varnode.getSize(), 8)));
        }
        return new CompositeStorage(pieces);
    }

    private static Storage stackStorage(VariableStorage storage, int expectedSize,
            String description) {
        Varnode varnode = storage.getFirstVarnode();
        if (varnode == null || varnode.getSize() != expectedSize) {
            return unavailable(OmissionReason.UNSUPPORTED_STORAGE,
                description + " stack slot does not exactly match its declared size");
        }
        return new StackStorage(storage.getStackOffset());
    }

    /**
     * Resolves a raw Ghidra stack coordinate against the analyzed stack-pointer
     * depth at each instruction. Unknown depths remain explicit unavailable gaps.
     */
    public static StackDepthProfile stackDepthProfile(Program program,
            Function function, TaskMonitor monitor) throws CancelledException {
        Register pointer = program.getCompilerSpec().getStackPointer();
        if (pointer == null) {
            return new StackDepthProfile("", List.of());
        }
        Register base = pointer.getBaseRegister();
        CallDepthChangeInfo depths = new CallDepthChangeInfo(function, monitor);
        List<StackDepthInterval> result = new ArrayList<>();
        InstructionIterator instructions = program.getListing()
            .getInstructions(function.getBody(), true);
        while (instructions.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = instructions.next();
            long start = instruction.getAddress().getOffset();
            long end = Math.addExact(instruction.getMaxAddress().getOffset(), 1L);
            int depth = depths.getSPDepth(instruction.getAddress());
            boolean known = depth != Function.UNKNOWN_STACK_DEPTH_CHANGE &&
                depth != Function.INVALID_STACK_DEPTH_CHANGE;
            if (!result.isEmpty()) {
                StackDepthInterval previous = result.get(result.size() - 1);
                if (previous.end() == start && previous.depth() == depth &&
                        previous.known() == known) {
                    result.set(result.size() - 1,
                        new StackDepthInterval(previous.start(), end, depth, known));
                    continue;
                }
            }
            result.add(new StackDepthInterval(start, end, depth, known));
        }
        return new StackDepthProfile(base.getName(), result);
    }

    /** Resolves one raw Ghidra stack coordinate against a shared function profile. */
    public static List<StorageInterval> stackIntervals(StackDepthProfile profile,
            StackStorage stack, TargetRegisterMap registers) {
        if (profile.registerName().isBlank()) {
            return List.of();
        }
        List<StorageInterval> result = new ArrayList<>();
        for (StackDepthInterval interval : profile.intervals()) {
            Storage resolved = interval.known()
                ? registers.registerRelative(profile.registerName(),
                    Math.subtractExact(stack.byteOffset(), (long) interval.depth()))
                : unavailable(OmissionReason.UNKNOWN_LIFETIME,
                    "stack-pointer depth is unknown at address 0x" +
                        Long.toUnsignedString(interval.start(), 16));
            result.add(new StorageInterval(interval.start(), interval.end(), resolved));
        }
        return List.copyOf(result);
    }

    static boolean writesRegister(Instruction instruction,
            Register parameter) {
        for (Object result : instruction.getResultObjects()) {
            if (result instanceof Register register && overlaps(parameter, register)) {
                return true;
            }
        }
        for (PcodeOp operation : instruction.getPcode()) {
            // STORE has no output varnode: input zero identifies its target
            // address space. Ghidra permits register-space stores, including
            // indirect offsets; conservatively kill the incoming value rather
            // than guessing an alias. Ordinary memory stores remain admissible.
            if (operation.getOpcode() == PcodeOp.STORE &&
                    (operation.getNumInputs() != 3 || operation.getOutput() != null ||
                        operation.getInput(0) == null || operation.getInput(1) == null ||
                        operation.getInput(2) == null || !operation.getInput(0).isConstant() ||
                        (int) operation.getInput(0).getOffset() ==
                            parameter.getAddress().getAddressSpace().getSpaceID())) {
                return true;
            }
            Varnode output = operation.getOutput();
            if (output == null || !output.isRegister()) {
                continue;
            }
            // Compare storage bytes as well as named register aliases: a raw
            // p-code output may cover a partial register without a named alias.
            long start = parameter.getAddress().getOffset();
            long end = Math.addExact(start, parameter.getMinimumByteSize());
            if (output.getAddress().getAddressSpace().equals(
                    parameter.getAddress().getAddressSpace()) &&
                    output.getOffset() < end &&
                    Math.addExact(output.getOffset(), output.getSize()) > start) {
                return true;
            }
        }
        return false;
    }

    private static boolean overlaps(Register first, Register second) {
        // Some listing result registers overlap storage without sharing a
        // named parent tree. Use the same physical-byte rule as raw outputs so
        // stable, original-prefix and backup proofs agree on every write.
        return first.contains(second) || second.contains(first) ||
            (first.getAddress().getAddressSpace().equals(second.getAddress().getAddressSpace()) &&
                first.getAddress().getOffset() < Math.addExact(second.getAddress().getOffset(),
                    second.getMinimumByteSize()) &&
                second.getAddress().getOffset() < Math.addExact(first.getAddress().getOffset(),
                    first.getMinimumByteSize()));
    }

    private static UnavailableStorage unavailable(OmissionReason reason,
            String diagnostic) {
        return new UnavailableStorage(reason, diagnostic);
    }
}
