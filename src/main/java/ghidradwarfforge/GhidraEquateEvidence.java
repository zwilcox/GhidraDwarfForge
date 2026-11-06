package ghidradwarfforge;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.DynamicHash;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.UniversalID;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.GhidraAnnotationInventory.EquateReference;
import ghidradwarfforge.GhidraAnnotationInventory.EquateValue;

/** Evidence for interpreting stored equates; never an original C declaration or lifetime. */
public final class GhidraEquateEvidence {
    public enum Status {
        RESOLVED, NOT_REQUESTED, NOT_ENUM, MALFORMED_ENUM_NAME, ENUM_VALUE_MISMATCH,
        MISSING_ENUM, WRONG_ENUM_TYPE, MISSING_ENUM_MEMBER, UNSUPPORTED_WIDTH,
        VALUE_OUT_OF_RANGE, NON_DEFAULT_SPACE, NO_INSTRUCTION, INVALID_OPERAND,
        NO_MATCHING_SCALAR, AMBIGUOUS_SCALAR, NO_DECOMPILER_EVIDENCE,
        UNRESOLVED_DYNAMIC_HASH, NOT_CONSTANT, DYNAMIC_VALUE_MISMATCH
    }

    /** Signedness belongs to this observation, not to the original expression's C type. */
    public record Value(int bits, boolean signed, long value) {
        public Value {
            if (!fits(value, bits, signed)) throw new IllegalArgumentException("equate value does not fit its evidence width");
        }
    }

    public record Resolution(Status status, Value value) {
        public Resolution {
            if (status == null || (status == Status.RESOLVED) != (value != null)) {
                throw new IllegalArgumentException("invalid equate resolution");
            }
        }
    }

    public record EnumEvidence(Status status, String typePath, List<String> memberNames, Value value) {
        public EnumEvidence {
            memberNames = List.copyOf(memberNames);
        }
    }

    /** Operand and dynamic hash are independent ownership fields; retain both observations. */
    public record ReferenceEvidence(EquateReference reference, Resolution scalar, Resolution dynamic) { }
    public record Evidence(EquateValue stored, EnumEvidence enumeration, List<ReferenceEvidence> references) {
        public Evidence {
            references = List.copyOf(references);
        }
    }

    private GhidraEquateEvidence() { }

    public static boolean fits(long value, int bits, boolean signed) {
        if (bits < 1 || bits > 64) return false;
        if (bits == 64) return true;
        if (!signed) return value >= 0 && (value >>> bits) == 0;
        long maximum = (1L << (bits - 1)) - 1;
        return value >= -maximum - 1 && value <= maximum;
    }

    public static List<Evidence> interpret(Program program, GhidraAnnotationInventory.Snapshot inventory,
            Map<EquateReference, Resolution> dynamic, TaskMonitor monitor) throws CancelledException {
        var output = new ArrayList<Evidence>();
        for (var equate : inventory.equates()) {
            monitor.checkCancelled();
            var references = new ArrayList<ReferenceEvidence>();
            for (var reference : equate.references()) {
                monitor.checkCancelled();
                Resolution high = reference.dynamicHash() == 0 ? absent(Status.NOT_REQUESTED)
                    : dynamic.getOrDefault(reference, absent(Status.NO_DECOMPILER_EVIDENCE));
                if (high.value() != null) {
                    int bits = high.value().bits();
                    long mask = bits == 64 ? -1L : -1L >>> (64 - bits);
                    // A high constant establishes bits, not signedness. Accept only
                    // an exact signed or unsigned representation of the stored value.
                    if ((!fits(equate.storedValue(), bits, true) && !fits(equate.storedValue(), bits, false)) ||
                            (equate.storedValue() & mask) != high.value().value()) {
                        high = absent(Status.DYNAMIC_VALUE_MISMATCH);
                    }
                }
                references.add(new ReferenceEvidence(reference, scalar(program, equate, reference, monitor), high));
            }
            output.add(new Evidence(equate, enumeration(program, equate, monitor), references));
        }
        monitor.checkCancelled();
        return List.copyOf(output);
    }

    private static Resolution scalar(Program program, EquateValue equate, EquateReference reference,
            TaskMonitor monitor) throws CancelledException {
        if (reference.operand() < 0) return absent(Status.NOT_REQUESTED);
        if (!reference.address().getAddressSpace().equals(program.getAddressFactory().getDefaultAddressSpace())) {
            return absent(Status.NON_DEFAULT_SPACE);
        }
        var instruction = program.getListing().getInstructionAt(reference.address());
        if (instruction == null) return absent(Status.NO_INSTRUCTION);
        if (reference.operand() >= instruction.getNumOperands()) return absent(Status.INVALID_OPERAND);
        Scalar match = null;
        for (Object object : instruction.getOpObjects(reference.operand())) {
            monitor.checkCancelled();
            if (object instanceof Scalar candidate && candidate.getValue() == equate.storedValue()) {
                if (match != null) return absent(Status.AMBIGUOUS_SCALAR);
                match = candidate;
            }
        }
        if (match == null) return absent(Status.NO_MATCHING_SCALAR);
        if (!fits(match.getValue(), match.bitLength(), match.isSigned())) return absent(Status.UNSUPPORTED_WIDTH);
        return new Resolution(Status.RESOLVED, new Value(match.bitLength(), match.isSigned(), match.getValue()));
    }

    private static EnumEvidence enumeration(Program program, EquateValue equate, TaskMonitor monitor)
            throws CancelledException {
        String name = equate.storedName();
        if (!name.startsWith("dtID")) return noEnum(Status.NOT_ENUM);
        // Ghidra 12.0.3 EquateManager formats dtID:<signed long UUID>:<signed long value>.
        // Its display helpers can throw for stale/malformed records, so validate first.
        String[] fields = name.split(":", -1);
        if (fields.length != 3 || !fields[0].equals("dtID") ||
                !fields[1].matches("-?[0-9]+") || !fields[2].matches("-?[0-9]+")) {
            return noEnum(Status.MALFORMED_ENUM_NAME);
        }
        long id;
        long encoded;
        try {
            id = Long.parseLong(fields[1]);
            encoded = Long.parseLong(fields[2]);
        }
        catch (NumberFormatException malformed) {
            return noEnum(Status.MALFORMED_ENUM_NAME);
        }
        if (encoded != equate.storedValue()) return noEnum(Status.ENUM_VALUE_MISMATCH);
        monitor.checkCancelled();
        var type = program.getDataTypeManager().findDataTypeForID(new UniversalID(id));
        if (type == null) return noEnum(Status.MISSING_ENUM);
        if (!(type instanceof Enum enumeration)) return noEnum(Status.WRONG_ENUM_TYPE);
        int bytes = enumeration.getLength();
        if (bytes < 1 || bytes > 8) return noEnum(Status.UNSUPPORTED_WIDTH);
        if (!fits(encoded, bytes * 8, enumeration.isSigned())) return noEnum(Status.VALUE_OUT_OF_RANGE);
        String[] names = enumeration.getNames(encoded);
        if (names == null || names.length == 0) return noEnum(Status.MISSING_ENUM_MEMBER);
        Arrays.sort(names);
        monitor.checkCancelled();
        return new EnumEvidence(Status.RESOLVED, enumeration.getPathName(), List.of(names),
            new Value(bytes * 8, enumeration.isSigned(), encoded));
    }

    private static EnumEvidence noEnum(Status status) {
        return new EnumEvidence(status, "", List.of(), null);
    }

    private static Resolution absent(Status status) {
        return new Resolution(status, null);
    }

    /** Captures small values while each HighFunction is live; does not retain its graph. */
    public static final class DynamicCollector {
        private final Map<Address, List<EquateReference>> byFunction = new HashMap<>();
        private final Map<EquateReference, Resolution> resolutions = new HashMap<>();

        public DynamicCollector(Program program, GhidraAnnotationInventory.Snapshot inventory,
                TaskMonitor monitor) throws CancelledException {
            for (var equate : inventory.equates()) {
                monitor.checkCancelled();
                for (var reference : equate.references()) {
                    monitor.checkCancelled();
                    if (reference.dynamicHash() == 0) continue;
                    if (!reference.address().getAddressSpace().equals(program.getAddressFactory().getDefaultAddressSpace())) {
                        resolutions.put(reference, absent(Status.NON_DEFAULT_SPACE));
                        continue;
                    }
                    var function = program.getFunctionManager().getFunctionContaining(reference.address());
                    if (function != null) byFunction.computeIfAbsent(function.getEntryPoint(), ignored -> new ArrayList<>()).add(reference);
                }
            }
            monitor.checkCancelled();
        }

        public void accept(HighFunction high, TaskMonitor monitor) throws CancelledException {
            monitor.checkCancelled();
            if (high == null) return;
            for (var reference : byFunction.getOrDefault(high.getFunction().getEntryPoint(), List.of())) {
                monitor.checkCancelled();
                var node = DynamicHash.findVarnode(high, reference.address(), reference.dynamicHash());
                Resolution resolved;
                if (node == null) resolved = absent(Status.UNRESOLVED_DYNAMIC_HASH);
                else if (!node.isConstant()) resolved = absent(Status.NOT_CONSTANT);
                else if (node.getSize() < 1 || node.getSize() > 8 || !fits(node.getOffset(), node.getSize() * 8, false)) {
                    resolved = absent(Status.UNSUPPORTED_WIDTH);
                }
                else resolved = new Resolution(Status.RESOLVED, new Value(node.getSize() * 8, false, node.getOffset()));
                var previous = resolutions.put(reference, resolved);
                if (previous != null && !previous.equals(resolved)) {
                    throw new IllegalStateException("Equate dynamic evidence changed during export");
                }
            }
            monitor.checkCancelled();
        }

        public Map<EquateReference, Resolution> snapshot(TaskMonitor monitor) throws CancelledException {
            monitor.checkCancelled();
            return Map.copyOf(resolutions);
        }
    }
}
