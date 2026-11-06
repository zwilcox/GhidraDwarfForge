package ghidradwarfforge;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CancellationException;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.source.SourceContextMode;

/** Bounded read-only observations of existing listing instructions, never a disassembler. */
public final class GhidraInstructionContext {
    public record Limits(int instructionsPerFunction, int bytesPerFunction,
            int bytesPerTrigger, int operationsPerInstruction) {
        public static final Limits DEFAULT = new Limits(16, 256, 64, 64);
        public Limits {
            if (instructionsPerFunction < 1 || bytesPerFunction < 1 || bytesPerTrigger < 1 ||
                    operationsPerInstruction < 1) throw new IllegalArgumentException("positive context limits required");
        }
    }

    /** One instance belongs to one function and one export; repeated context is referenced, not copied. */
    public static final class Budget {
        private final Address owner;
        private final Program program;
        private final Limits limits;
        private final Set<Address> observed = new HashSet<>();
        private int bytes;
        public Budget(Function function, Limits limits) {
            owner = Objects.requireNonNull(function).getEntryPoint();
            program = function.getProgram();
            this.limits = Objects.requireNonNull(limits);
        }
        public int instructions() { return observed.size(); }
        public int bytes() { return bytes; }
    }

    public record ContextRegister(String name, int bits, String mask, String value) { }
    public record Operation(Address address, int sequence, String mnemonic,
            String output, List<String> inputs) {
        public Operation { inputs = List.copyOf(inputs); }
    }
    public record Pcode(List<Operation> raw, List<Operation> effective, List<String> diagnostics) {
        public Pcode {
            raw = List.copyOf(raw);
            effective = List.copyOf(effective);
            diagnostics = List.copyOf(diagnostics);
        }
    }
    public record Observation(Address start, Address listingEnd, int listingLength, int parsedLength,
            byte[] bytes, String byteStatus, String assembly, ContextRegister context,
            boolean inDelaySlot, int delaySlotDepth, String flowOverride, Pcode pcode) {
        public Observation { bytes = bytes.clone(); }
        @Override public byte[] bytes() { return bytes.clone(); }
    }
    public record Snapshot(String language, String compiler, Address function, Address focus,
            Address rangeStart, Address rangeEnd, List<Observation> instructions,
            List<Address> reused, List<String> diagnostics) {
        public Snapshot {
            instructions = List.copyOf(instructions);
            reused = List.copyOf(reused);
            diagnostics = List.copyOf(diagnostics);
        }
    }

    private GhidraInstructionContext() { }

    public static Snapshot read(Program program, Function function, Address focus, SourceContextMode mode,
            Budget budget, TaskMonitor monitor) throws CancelledException {
        Objects.requireNonNull(program);
        Objects.requireNonNull(function);
        Objects.requireNonNull(focus);
        Objects.requireNonNull(mode);
        Objects.requireNonNull(budget);
        monitor.checkCancelled();
        if (function.getProgram() != program || budget.program != program || !budget.owner.equals(function.getEntryPoint())) {
            throw new IllegalArgumentException("context budget belongs to a different function");
        }
        var observations = new ArrayList<Observation>();
        var reused = new ArrayList<Address>();
        var diagnostics = new ArrayList<String>();
        AddressRange range = function.getBody().getRangeContaining(focus);
        if (mode == SourceContextMode.OFF) return snapshot(program, function, focus, range, observations, reused, diagnostics);
        if (range == null) {
            diagnostics.add("FOCUS_OUTSIDE_FUNCTION_BODY");
            return snapshot(program, function, focus, null, observations, reused, diagnostics);
        }
        var instruction = program.getListing().getInstructionContaining(focus);
        if (instruction == null) {
            int available = Math.min(budget.limits.bytesPerTrigger(), budget.limits.bytesPerFunction() - budget.bytes);
            var bytes = readBytes(program, focus, range, available, available, monitor);
            budget.bytes += bytes.bytes().length;
            observations.add(new Observation(focus, null, 0, 0, bytes.bytes(),
                "NO_LISTING_INSTRUCTION; " + bytes.status(), null, context(program, focus), false, 0, null,
                new Pcode(List.of(), List.of(), List.of("NO_LISTING_INSTRUCTION"))));
            return snapshot(program, function, focus, range, observations, reused, diagnostics);
        }
        // The focus is first so a large predecessor cannot consume its byte budget.
        var selected = new ArrayList<Instruction>();
        selected.add(instruction);
        var previous = program.getListing().getInstructionBefore(instruction.getMinAddress());
        if (previous != null && instruction.getMinAddress().equals(previous.getMaxAddress().next())) selected.add(previous);
        var next = program.getListing().getInstructionAfter(instruction.getMinAddress());
        if (next != null && next.getMinAddress().equals(instruction.getMaxAddress().next())) selected.add(next);
        int triggerBytes = 0;
        for (var item : selected) {
            monitor.checkCancelled();
            if (!range.contains(item.getMinAddress()) ||
                    (!range.contains(item.getMaxAddress()) && item != instruction)) {
                diagnostics.add("INSTRUCTION_OUTSIDE_SELECTED_BODY_RANGE:" + item.getMinAddress().toString(true));
                continue;
            }
            if (budget.observed.contains(item.getMinAddress())) {
                reused.add(item.getMinAddress());
                continue;
            }
            if (budget.observed.size() >= budget.limits.instructionsPerFunction()) {
                diagnostics.add("FUNCTION_INSTRUCTION_LIMIT; further instructions not visited");
                break;
            }
            int available = Math.min(budget.limits.bytesPerTrigger() - triggerBytes,
                budget.limits.bytesPerFunction() - budget.bytes);
            if (available <= 0) {
                diagnostics.add("CONTEXT_BYTE_LIMIT; further instructions not visited");
                break;
            }
            int length = item.getLength();
            int parsed = item.getParsedLength();
            var bytes = readBytes(program, item.getMinAddress(), range, length, available, monitor);
            budget.bytes += bytes.bytes().length;
            triggerBytes += bytes.bytes().length;
            boolean complete = length > 0 && parsed > 0 && bytes.bytes().length >= parsed &&
                bytes.bytes().length == length && bytes.status().equals("COMPLETE");
            String assembly = complete && mode.assembly() ? item.toString() : null;
            Pcode pcode = complete && mode.pcode() ? pcode(item, range, budget.limits.operationsPerInstruction(), monitor)
                : new Pcode(List.of(), List.of(), List.of(complete ? "PCODE_NOT_REQUESTED" : "INCOMPLETE_INSTRUCTION_BYTES"));
            observations.add(new Observation(item.getMinAddress(), item.getMaxAddress(), length, parsed, bytes.bytes(),
                complete ? "COMPLETE" : bytes.status().equals("COMPLETE") ? "INCOMPLETE_PARSED_BYTES" : bytes.status(),
                assembly, context(program, item.getMinAddress()), item.isInDelaySlot(), item.getDelaySlotDepth(),
                item.getFlowOverride().name(), pcode));
            budget.observed.add(item.getMinAddress());
        }
        monitor.checkCancelled();
        return snapshot(program, function, focus, range, observations, reused, diagnostics);
    }

    private record Bytes(byte[] bytes, String status) {
        Bytes { bytes = bytes.clone(); }
        @Override public byte[] bytes() { return bytes.clone(); }
    }

    private static Bytes readBytes(Program program, Address address, AddressRange range, int requested,
            int allowed, TaskMonitor monitor) throws CancelledException {
        int length = Math.max(0, Math.min(requested, allowed));
        byte[] result = new byte[length];
        int count = 0;
        String status = requested > allowed ? "BYTE_LIMIT" : "COMPLETE";
        Address current = address;
        while (count < length) {
            monitor.checkCancelled();
            if (current == null || !range.contains(current)) { status = "BODY_RANGE_END"; break; }
            try { result[count] = program.getMemory().getByte(current); }
            catch (MemoryAccessException unavailable) { status = "UNREADABLE_MEMORY"; break; }
            count++;
            current = current.next();
        }
        if (length == 0) status = "BYTE_LIMIT";
        return new Bytes(java.util.Arrays.copyOf(result, count), status);
    }

    private static ContextRegister context(Program program, Address address) {
        var programContext = program.getProgramContext();
        var base = programContext.getBaseContextRegister();
        if (base == null) return null;
        var value = programContext.getRegisterValue(base, address);
        return new ContextRegister(base.getName(), base.getBitLength(), value == null ? null : value.getValueMask().toString(16),
            value == null ? null : value.getUnsignedValueIgnoreMask().toString(16));
    }

    private static Pcode pcode(Instruction instruction, AddressRange range, int limit, TaskMonitor monitor)
            throws CancelledException {
        var raw = new ArrayList<Operation>();
        var effective = new ArrayList<Operation>();
        var diagnostics = new ArrayList<String>();
        int consumed = 0;
        for (boolean overridden : new boolean[] {false, true}) {
            monitor.checkCancelled();
            int remaining = limit - consumed;
            String label = overridden ? "EFFECTIVE" : "RAW";
            if (remaining == 0) {
                diagnostics.add(label + "_PCODE_NOT_VISITED:OPERATION_LIMIT");
                continue;
            }
            PcodeOp[] operations;
            try { operations = instruction.getPcode(overridden); }
            catch (CancellationException cancelled) { throw cancelled; }
            catch (RuntimeException unavailable) {
                diagnostics.add(label + "_PCODE_UNAVAILABLE:" + unavailable.getClass().getSimpleName());
                continue;
            }
            var destination = overridden ? effective : raw;
            for (int index = 0; index < operations.length && index < remaining; index++) {
                monitor.checkCancelled();
                consumed++;
                var operation = operations[index];
                var address = operation.getSeqnum().getTarget();
                if (!range.contains(address)) {
                    diagnostics.add(label + "_PCODE_OUTSIDE_BODY_RANGE:" + address.toString(true));
                    continue;
                }
                var inputs = new ArrayList<String>();
                int inputLimit = Math.min(operation.getNumInputs(), 64);
                for (int input = 0; input < inputLimit; input++) {
                    monitor.checkCancelled();
                    inputs.add(operation.getInput(input).toString());
                }
                if (inputLimit != operation.getNumInputs()) diagnostics.add(label + "_PCODE_INPUT_LIMIT:" +
                    (operation.getNumInputs() - inputLimit) + " operands omitted");
                destination.add(new Operation(address, operation.getSeqnum().getTime(), operation.getMnemonic(),
                    operation.getOutput() == null ? null : operation.getOutput().toString(), inputs));
            }
            if (operations.length > remaining) diagnostics.add(label + "_PCODE_OPERATION_LIMIT:" +
                (operations.length - remaining) + " operations omitted");
        }
        return new Pcode(raw, effective, diagnostics);
    }

    private static Snapshot snapshot(Program program, Function function, Address focus, AddressRange range,
            List<Observation> instructions, List<Address> reused, List<String> diagnostics) {
        return new Snapshot(program.getLanguageID().toString(), program.getCompilerSpec().getCompilerSpecID().toString(),
            function.getEntryPoint(), focus, range == null ? null : range.getMinAddress(), range == null ? null : range.getMaxAddress(),
            instructions, reused, diagnostics);
    }
}
