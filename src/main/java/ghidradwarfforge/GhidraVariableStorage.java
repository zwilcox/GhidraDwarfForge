package ghidradwarfforge;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.function.CallDepthChangeInfo;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
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
        Storage mapped = registers.register(base.getName(),
            register.getLeastSignificantBitInBaseRegister(), Math.toIntExact(requiredBits));
        if (!mapped.available()) {
            return mapped;
        }
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
            if (writesRegister(program, instruction, base)) {
                return unavailable(OmissionReason.REGISTER_MODIFIED,
                    "function writes " + description + " register " + base.getName() +
                        " at " + instruction.getAddress());
            }
        }
        return mapped;
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

    private static boolean writesRegister(Program program, Instruction instruction,
            Register parameter) {
        for (Object result : instruction.getResultObjects()) {
            if (result instanceof Register register && overlaps(parameter, register)) {
                return true;
            }
        }
        for (PcodeOp operation : instruction.getPcode()) {
            Varnode output = operation.getOutput();
            if (output == null || !output.isRegister()) {
                continue;
            }
            Register register = program.getRegister(output);
            if (register != null && overlaps(parameter, register)) {
                return true;
            }
        }
        return false;
    }

    private static boolean overlaps(Register first, Register second) {
        return first.contains(second) || second.contains(first);
    }

    private static UnavailableStorage unavailable(OmissionReason reason,
            String diagnostic) {
        return new UnavailableStorage(reason, diagnostic);
    }
}
