package ghidradwarfforge;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.cmd.function.CallDepthChangeInfo;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.SleighLanguageDescription;
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
        // Dynamic parameters can have effective storage while their symbol row is unassigned.
        if (storage == null || storage.isUnassignedStorage()) {
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
     * Refines an otherwise rejected incoming register or register/stack parameter. The value
     * exists at the first writing instruction (before it executes), and becomes
     * unavailable at its fall-through address unless a separate ordered p-code
     * proof establishes one completed register backup before that instruction.
     * A composite has only a complete incoming prefix and a whole-value tail;
     * no surviving piece or compound backup is inferred.
     * An empty result leaves the original conservative rejection unchanged.
     */
    public static List<StorageInterval> parameterPrefix(Program program, Function function,
            Parameter parameter, TargetRegisterMap registers, Storage rejected,
            TaskMonitor monitor) throws CancelledException {
        if (rejected instanceof UnavailableStorage && hasStackPiece(parameter.getVariableStorage())) {
            return mixedParameterPrefix(program, function, parameter, registers, monitor);
        }
        if (!(rejected instanceof UnavailableStorage unavailable) ||
                unavailable.reason() != OmissionReason.REGISTER_MODIFIED) {
            return List.of();
        }
        VariableStorage storage = parameter.getVariableStorage();
        if (storage == null) {
            return List.of();
        }
        boolean composite = storage.getVarnodeCount() > 1;
        if (!composite && (storage.getVarnodeCount() != 1 || !storage.isRegisterStorage())) {
            return List.of();
        }
        Register register = composite ? null : parameter.getRegister();
        if ((!composite && register == null) ||
                function.getBody().getNumAddressRanges() != 1 ||
                !function.getEntryPoint().equals(function.getBody().getMinAddress())) {
            return List.of();
        }
        Storage mapped;
        List<Register> bases = new ArrayList<>();
        if (composite) {
            // The first REGISTER_MODIFIED result may have hidden invalid later
            // pieces. Revalidate the entire value before constructing intervals.
            var formal = parameter.getFormalDataType();
            int bytes = parameter.getLength();
            if (bytes <= 0 || formal == null || formal.getLength() != bytes ||
                    storage.size() != bytes || !storage.isValid() || storage.isBadStorage() ||
                    storage.isUnassignedStorage() || storage.isForcedIndirect()) {
                return List.of();
            }
            Varnode[] nodes = storage.getVarnodes();
            if (nodes == null || nodes.length != storage.getVarnodeCount()) {
                return List.of();
            }
            List<Piece> pieces = new ArrayList<>();
            var pieceEnds = new ArrayList<ghidra.program.model.address.Address>();
            long total = 0;
            for (int index = 0; index < nodes.length; index++) {
                monitor.checkCancelled();
                Varnode node = nodes[index];
                if (node == null || !node.isRegister() || node.getSize() <= 0) {
                    return List.of();
                }
                Register pieceRegister = program.getRegister(node);
                // Big-endian low slices need not start at the full register's
                // address. Require the language's exact address/size lookup;
                // mappedRegister preserves its LSB-relative slice semantics.
                if (pieceRegister == null || pieceRegister != program.getLanguage()
                        .getRegister(node.getAddress(), node.getSize())) {
                    return List.of();
                }
                Storage piece = mappedRegister(pieceRegister, node.getSize(), registers,
                    "parameter piece");
                if (!(piece instanceof RegisterStorage mappedPiece)) {
                    return List.of();
                }
                ghidra.program.model.address.Address nodeEnd;
                try {
                    nodeEnd = node.getAddress().addNoWrap(node.getSize() - 1L);
                }
                catch (ghidra.program.model.address.AddressOverflowException invalidRange) {
                    return List.of();
                }
                for (int previous = 0; previous < index; previous++) {
                    monitor.checkCancelled();
                    Varnode other = nodes[previous];
                    if (node.getAddress().getAddressSpace().equals(other.getAddress().getAddressSpace()) &&
                            node.getAddress().compareTo(pieceEnds.get(previous)) <= 0 &&
                            other.getAddress().compareTo(nodeEnd) <= 0) {
                        return List.of();
                    }
                }
                total += node.getSize();
                if (total > bytes) {
                    return List.of();
                }
                pieces.add(new Piece(mappedPiece, mappedPiece.bitSize()));
                pieceEnds.add(nodeEnd);
                bases.add(pieceRegister.getBaseRegister());
            }
            if (total != bytes) {
                return List.of();
            }
            mapped = new CompositeStorage(program.getLanguage().isBigEndian() ? pieces : pieces.reversed());
        }
        else {
            mapped = mappedRegister(register, parameter.getLength(), registers, "parameter");
            if (!mapped.available()) {
                return List.of();
            }
        }
        List<Instruction> instructions = prefixInstructions(program, function, monitor);
        if (instructions == null) {
            return List.of();
        }
        long start = function.getEntryPoint().getOffset();
        long end = Math.addExact(function.getBody().getMaxAddress().getOffset(), 1);
        var calls = composite ? Map.<ghidra.program.model.address.Address, DirectLeafCalls.Leaf>of()
            : DirectLeafCalls.inspect(program, instructions, monitor);
        if (calls == null) {
            return List.of();
        }
        long boundary = composite
            ? registerPrefixEnd(start, end, instructions, bases, true, monitor)
            : registerPrefixEnd(start, end, instructions, register.getBaseRegister(), calls, monitor);
        if (boundary <= start) {
            return List.of();
        }
        List<StorageInterval> result = new ArrayList<>();
        result.add(new StorageInterval(start, boundary, mapped));
        var formalType = parameter.getFormalDataType();
        // A storage-width copy is not evidence for a differently sized formal
        // value. Keep the established prefix when this narrower proof fails.
        RegisterCopyLifetime.Backup backup = !composite && formalType != null &&
                formalType.getLength() == parameter.getLength() &&
                storage.size() == parameter.getLength()
            ? RegisterCopyLifetime.prove(program, start, end, instructions,
                storage.getFirstVarnode(), parameter.getLength(), registers, calls, monitor)
            : null;
        if (backup != null) {
            result.add(new StorageInterval(boundary, backup.end(), backup.storage()));
            boundary = backup.end();
        }
        boolean spilled = false;
        if (backup == null && !composite && formalType != null &&
                formalType.getLength() == parameter.getLength() && storage.size() == parameter.getLength() &&
                function.getProgram() == program && storage.getProgramArchitecture() == program &&
                parameter.getFunction() == function && parameter.getOrdinal() >= 0 &&
                function.getParameter(parameter.getOrdinal()) == parameter && parameter.getFirstUseOffset() == 0 &&
                storage.isValid() && !storage.isBadStorage() && !storage.isForcedIndirect()) {
            var spill = StackSpillLifetime.prove(program, start, end, instructions,
                storage.getFirstVarnode(), parameter.getLength(), registers, monitor);
            if (spill != null) {
                result.add(new StorageInterval(boundary, spill.end(), spill.storage()));
                boundary = spill.end();
                spilled = true;
            }
        }
        if (boundary < end) {
            result.add(new StorageInterval(boundary, end, unavailable(
                spilled ? OmissionReason.UNKNOWN_LIFETIME : OmissionReason.REGISTER_MODIFIED,
                (spilled ? "proven parameter stack spill may have changed before address 0x" :
                    "proven parameter register storage was overwritten before address 0x") +
                    Long.toHexString(boundary) + "; later storage is not established")));
        }
        return List.copyOf(result);
    }

    static boolean hasStackPiece(VariableStorage storage) {
        if (storage == null || storage.getVarnodeCount() < 2 || storage.getVarnodes() == null) {
            return false;
        }
        for (Varnode node : storage.getVarnodes()) {
            if (node != null && node.getAddress().isStackAddress()) {
                return true;
            }
        }
        return false;
    }

    private static List<StorageInterval> mixedParameterPrefix(Program program, Function function,
            Parameter parameter, TargetRegisterMap registers, TaskMonitor monitor)
            throws CancelledException {
        monitor.checkCancelled();
        VariableStorage storage = parameter.getVariableStorage();
        var formal = parameter.getFormalDataType();
        int bytes = parameter.getLength();
        // Stack analysis and listing instructions must describe the same
        // attached parameter/function/program, not a detached storage sketch.
        if (function.getProgram() != program || storage.getProgramArchitecture() != program ||
                parameter.getFunction() != function ||
                parameter.getOrdinal() < 0 || function.getParameter(parameter.getOrdinal()) != parameter ||
                parameter.getFirstUseOffset() != 0 ||
                bytes <= 0 || formal == null || formal.getLength() != bytes ||
                storage.size() != bytes || !storage.isValid() || storage.isBadStorage() ||
                storage.isForcedIndirect() || storage.isUnassignedStorage() ||
                function.getBody().getNumAddressRanges() != 1 ||
                !function.getEntryPoint().equals(function.getBody().getMinAddress())) {
            return List.of();
        }
        Varnode[] nodes = storage.getVarnodes();
        if (nodes.length != storage.getVarnodeCount()) {
            return List.of();
        }
        List<Piece> pieces = new ArrayList<>();
        List<Register> bases = new ArrayList<>();
        var ends = new ArrayList<ghidra.program.model.address.Address>();
        long total = 0;
        for (int index = 0; index < nodes.length; index++) {
            monitor.checkCancelled();
            Varnode node = nodes[index];
            if (node == null || node.getSize() <= 0) {
                return List.of();
            }
            Storage piece;
            if (node.isRegister()) {
                Register register = program.getRegister(node);
                if (register == null || register != program.getLanguage()
                        .getRegister(node.getAddress(), node.getSize())) {
                    return List.of();
                }
                piece = mappedRegister(register, node.getSize(), registers, "incoming mixed piece");
                if (!(piece instanceof RegisterStorage)) {
                    return List.of();
                }
                bases.add(register.getBaseRegister());
            }
            else if (node.getAddress().isStackAddress()) {
                // Ghidra permits one non-register carrier at a target-dependent
                // end of the join. Check the loaded-language convention.
                int stackIndex = program.getLanguage().isBigEndian() ? nodes.length - 1 : 0;
                if (index != stackIndex || node.getAddress().getAddressSpace() !=
                        program.getAddressFactory().getStackSpace() ||
                        (node.getOffset() < 0 && node.getOffset() > -((long) node.getSize()))) {
                    return List.of();
                }
                piece = new StackStorage(node.getOffset());
            }
            else {
                return List.of();
            }
            ghidra.program.model.address.Address end;
            try {
                end = node.getAddress().addNoWrap(node.getSize() - 1L);
            }
            catch (ghidra.program.model.address.AddressOverflowException invalid) {
                return List.of();
            }
            for (int previous = 0; previous < index; previous++) {
                monitor.checkCancelled();
                if (node.getAddress().getAddressSpace().equals(nodes[previous].getAddress().getAddressSpace()) &&
                        node.getAddress().compareTo(ends.get(previous)) <= 0 &&
                        nodes[previous].getAddress().compareTo(end) <= 0) {
                    return List.of();
                }
            }
            total += node.getSize();
            if (total > bytes) {
                return List.of();
            }
            ends.add(end);
            pieces.add(new Piece(piece, Math.multiplyExact(node.getSize(), 8)));
        }
        if (total != bytes || bases.isEmpty()) {
            return List.of();
        }
        List<Instruction> instructions = prefixInstructions(program, function, monitor);
        if (instructions == null) {
            return List.of();
        }
        long start = function.getEntryPoint().getOffset();
        long end = Math.addExact(function.getBody().getMaxAddress().getOffset(), 1);
        // Any possible memory write ends this first bounded proof, even a
        // store that might target a disjoint frame slot. No alias inference.
        long boundary = registerPrefixEnd(start, end, instructions, bases, true,
            Map.of(), true, monitor);
        if (boundary <= start) {
            return List.of();
        }
        StackDepthProfile profile = stackDepthProfile(program, function, monitor);
        if (profile.intervals().isEmpty() || profile.registerName().isBlank() ||
                !profile.intervals().getFirst().known() || profile.intervals().getFirst().depth() != 0 ||
                profile.intervals().getFirst().start() != start) {
            return List.of();
        }
        if (!program.getLanguage().isBigEndian()) {
            pieces = pieces.reversed();
        }
        List<StorageInterval> result = new ArrayList<>();
        for (StackDepthInterval interval : profile.intervals()) {
            monitor.checkCancelled();
            long limit = Math.min(boundary, interval.end());
            if (interval.start() >= limit) {
                break;
            }
            Storage value = unavailable(OmissionReason.UNKNOWN_LIFETIME,
                "incoming mixed storage has no proven stack-pointer depth");
            if (interval.known()) {
                List<Piece> resolved = new ArrayList<>();
                for (Piece piece : pieces) {
                    monitor.checkCancelled();
                    Storage location = piece.storage() instanceof StackStorage stack
                        ? registers.registerRelative(profile.registerName(),
                            Math.subtractExact(stack.byteOffset(), (long) interval.depth()))
                        : piece.storage();
                    if (!location.available()) {
                        return List.of();
                    }
                    resolved.add(new Piece(location, piece.bitSize()));
                }
                value = new CompositeStorage(resolved);
            }
            result.add(new StorageInterval(interval.start(), limit, value));
        }
        if (boundary < end) {
            result.add(new StorageInterval(boundary, end, unavailable(OmissionReason.UNKNOWN_LIFETIME,
                "incoming mixed storage may have been overwritten; later storage is not established")));
        }
        return List.copyOf(result);
    }

    private static boolean writesMemory(Instruction instruction) {
        for (Object output : instruction.getResultObjects()) {
            if (output instanceof ghidra.program.model.address.Address address &&
                    address.getAddressSpace().isMemorySpace()) {
                return true;
            }
        }
        for (PcodeOp operation : instruction.getPcode()) {
            if (operation.getOpcode() == PcodeOp.STORE || (operation.getOutput() != null &&
                    operation.getOutput().getAddress().getAddressSpace().isMemorySpace())) {
                return true;
            }
        }
        return false;
    }

    private static List<Instruction> prefixInstructions(Program program, Function function,
            TaskMonitor monitor) throws CancelledException {
        List<Instruction> instructions = new ArrayList<>();
        var instructionsByAddress = new HashMap<ghidra.program.model.address.Address, Instruction>();
        var iterator = program.getListing().getInstructions(function.getBody(), true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = iterator.next();
            for (PcodeOp operation : instruction.getPcode()) {
                monitor.checkCancelled();
                if (unprovenStore(program, operation)) {
                    return null;
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
                        return null;
                    }
                }
            }
        }
        return List.copyOf(instructions);
    }

    /** Exact fully decoded, ordinary straight-line leaf proof; -1 rejects it. */
    static long registerPrefixEnd(long start, long end, List<Instruction> instructions,
            Register register, TaskMonitor monitor) throws CancelledException {
        return registerPrefixEnd(start, end, instructions, List.of(register), false, monitor);
    }

    private static long registerPrefixEnd(long start, long end, List<Instruction> instructions,
            List<Register> registers, boolean exactDecodedLength, TaskMonitor monitor)
            throws CancelledException {
        return registerPrefixEnd(start, end, instructions, registers, exactDecodedLength,
            Map.of(), monitor);
    }

    static long registerPrefixEnd(long start, long end, List<Instruction> instructions,
            Register register, Map<ghidra.program.model.address.Address, DirectLeafCalls.Leaf> calls,
            TaskMonitor monitor) throws CancelledException {
        return registerPrefixEnd(start, end, instructions, List.of(register), !calls.isEmpty(),
            calls, monitor);
    }

    private static long registerPrefixEnd(long start, long end, List<Instruction> instructions,
            List<Register> registers, boolean exactDecodedLength,
            Map<ghidra.program.model.address.Address, DirectLeafCalls.Leaf> calls, TaskMonitor monitor)
            throws CancelledException {
        return registerPrefixEnd(start, end, instructions, registers, exactDecodedLength,
            calls, false, monitor);
    }

    private static long registerPrefixEnd(long start, long end, List<Instruction> instructions,
            List<Register> registers, boolean exactDecodedLength,
            Map<ghidra.program.model.address.Address, DirectLeafCalls.Leaf> calls,
            boolean stopAtMemoryWrite, TaskMonitor monitor) throws CancelledException {
        long expected = start;
        long firstWriteEnd = -1;
        boolean returned = false;
        for (Instruction instruction : instructions) {
            monitor.checkCancelled();
            if (returned || instruction.getAddress().getOffset() != expected ||
                    instruction.isInDelaySlot() || instruction.getDelaySlotDepth() != 0 ||
                    instruction.getFlowOverride() != FlowOverride.NONE ||
                    (exactDecodedLength && (instruction.isLengthOverridden() ||
                        instruction.isFallThroughOverridden() || instruction.getLength() <= 0 ||
                        instruction.getParsedLength() != instruction.getLength()))) {
                return -1;
            }
            long next = Math.addExact(instruction.getMaxAddress().getOffset(), 1);
            if (next <= expected || next > end ||
                    (exactDecodedLength && next != Math.addExact(expected, instruction.getLength()))) {
                return -1;
            }
            boolean returns = false;
            PcodeOp[] operations = instruction.getPcode();
            for (PcodeOp operation : operations) {
                if (exactDecodedLength) {
                    monitor.checkCancelled();
                }
                switch (operation.getOpcode()) {
                    case PcodeOp.BRANCH, PcodeOp.CBRANCH, PcodeOp.BRANCHIND,
                        PcodeOp.CALLIND,
                        PcodeOp.UNIMPLEMENTED -> { return -1; }
                    case PcodeOp.CALLOTHER -> {
                        // Only the state before this final machine return is
                        // observable in the invocation. Reuse the stable-register
                        // boundary proof without treating any userop as pure.
                        if (next != end || !ordinaryTerminalReturn(instruction, operations) ||
                                operation.getNumInputs() == 0 || operation.getInput(0) == null ||
                                !operation.getInput(0).isConstant() ||
                                instruction.isLengthOverridden() || instruction.isFallThroughOverridden() ||
                                instruction.getLength() <= 0 ||
                                instruction.getParsedLength() != instruction.getLength() ||
                                next != Math.addExact(expected, instruction.getLength())) {
                            return -1;
                        }
                    }
                    case PcodeOp.CALL -> {
                        // Only a backup established before the original's
                        // overwrite can cross a call; never infer a new prefix
                        // from ABI metadata or a call instruction itself.
                        if (firstWriteEnd == -1 || !calls.containsKey(instruction.getAddress())) {
                            return -1;
                        }
                    }
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
            else if (!(flow.isFallthrough() || calls.containsKey(instruction.getAddress())) ||
                    instruction.getFallThrough() == null ||
                    instruction.getFallThrough().getOffset() != next) {
                return -1;
            }
            if (firstWriteEnd == -1 && stopAtMemoryWrite && writesMemory(instruction)) {
                firstWriteEnd = next;
            }
            if (firstWriteEnd == -1) {
                for (Register register : registers) {
                    if (exactDecodedLength) {
                        monitor.checkCancelled();
                    }
                    if (writesRegister(instruction, register)) {
                        firstWriteEnd = next;
                        break;
                    }
                }
            }
            expected = next;
        }
        return returned && expected == end
            ? firstWriteEnd == -1 && stopAtMemoryWrite ? end : firstWriteEnd : -1;
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
        monitor.checkCancelled();
        var body = function.getBody();
        var uncovered = new AddressSet(body);
        boolean incomplete = body.isEmpty();
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
            // Listing iteration returns existing instructions, not a proof that
            // all declared body bytes have been decoded. Keep address sets so
            // discontiguous bodies do not turn their intervening gaps into code.
            if (instruction.isLengthOverridden() || instruction.getLength() <= 0 ||
                    instruction.getLength() != instruction.getParsedLength() ||
                    !body.contains(instruction.getAddress(), instruction.getMaxAddress())) {
                incomplete = true;
            }
            else {
                uncovered.delete(instruction.getAddress(), instruction.getMaxAddress());
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
        if (incomplete || !uncovered.isEmpty()) {
            return unavailable(OmissionReason.UNKNOWN_LIFETIME,
                "incomplete instruction coverage prevents proving the " + description +
                    " register " + base.getName() + " stable");
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
        if (space == null || !space.isMemorySpace()) {
            return true;
        }
        int offsetBytes = operation.getInput(1).getSize();
        if (offsetBytes == space.getPointerSize()) {
            return false;
        }
        return !declaredTruncatedMemory(program, space, offsetBytes);
    }

    private static boolean declaredTruncatedMemory(Program program, AddressSpace space,
            int offsetBytes) {
        // A loaded Sleigh language can retain wider STORE operands while its
        // declared RAM space is truncated. Input 0 still selects RAM; input 1
        // is read as an offset, never written as a register. Bound this extra
        // case to the concrete long-offset domain, without guessing SLA width.
        // This only removes the width-based opaque-effect rejection. The
        // separate writesRegister check still rejects stores into the tracked
        // register's space, including memory-mapped registers. It proves no
        // offset validity or successful access (range checks can still fail).
        if (offsetBytes <= space.getPointerSize() || offsetBytes > Long.BYTES ||
                space.getType() != AddressSpace.TYPE_RAM || space.isOverlaySpace() ||
                space.getPhysicalSpace() != space || space.getAddressableUnitSize() <= 0 ||
                !(program.getLanguage() instanceof SleighLanguage language) ||
                !(language.getLanguageDescription() instanceof SleighLanguageDescription description)) {
            return false;
        }
        // ProgramAddressFactory retains the language's physical space objects.
        // Require identity through both IDs and names, not a matching RAM name
        // supplied by a program overlay or a different address factory.
        var languageFactory = language.getAddressFactory();
        if (languageFactory.getAddressSpace(space.getSpaceID()) != space ||
                languageFactory.getAddressSpace(space.getName()) != space ||
                program.getAddressFactory().getAddressSpace(space.getName()) != space ||
                !description.getTruncatedSpaceNames().contains(space.getName())) {
            return false;
        }
        int truncatedBytes = description.getTruncatedSpaceSize(space.getName());
        return truncatedBytes > 0 && truncatedBytes < offsetBytes &&
            truncatedBytes == space.getPointerSize() &&
            space.getSize() == truncatedBytes * Byte.SIZE;
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
        var pair = registers.registerPairs().get(register.getName());
        if (pair != null) {
            // The isolated target description supplies the ABI meaning. The
            // loaded language must independently agree on both physical slices.
            if (register != base || requiredBits != register.getBitLength()) {
                return unavailable(OmissionReason.UNSUPPORTED_STORAGE,
                    description + " is not the complete paired register");
            }
            List<Piece> pieces = new ArrayList<>();
            long bits = 0;
            for (var expected : pair) {
                Register child = null;
                for (Register candidate : register.getChildRegisters()) {
                    if (candidate.getName().equals(expected.registerName())) {
                        child = candidate;
                        break;
                    }
                }
                if (child == null || child.getBaseRegister() != base ||
                        child.getLeastSignificantBitInBaseRegister() != expected.baseBitOffset() ||
                        child.getBitLength() != expected.bitSize()) {
                    return unavailable(OmissionReason.UNSUPPORTED_STORAGE,
                        description + " paired register disagrees with the loaded language");
                }
                pieces.add(new Piece(registers.register(child.getName(), 0, expected.bitSize()),
                    expected.bitSize()));
                bits += expected.bitSize();
            }
            if (bits != requiredBits) {
                return unavailable(OmissionReason.UNSUPPORTED_STORAGE,
                    description + " paired pieces do not cover its size");
            }
            return new CompositeStorage(pieces);
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
        // Ghidra's AddressXML serializes join pieces most-significant first,
        // for both computed and explicit storage. Preserve that order while
        // checking each piece so the existing first omission stays unchanged.
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
        // DWARF concatenates pieces in object memory order. Normalize only
        // the completed list; each register's LSB-relative slice is unchanged.
        return new CompositeStorage(program.getLanguage().isBigEndian() ? pieces : pieces.reversed());
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
