package ghidradwarfforge.calls;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.FlowType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.AddressNormalizer;
import ghidradwarfforge.GhidraTargetAgreement;
import ghidradwarfforge.elf.ElfCodeBytes;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.elf.ElfRelocationEffects;

/**
 * Immutable listing and original-image evidence. A branch to another function
 * is only a candidate: return/stack restoration and argument-value proofs belong
 * to the subsequent analysis. This inventory never grants DW_AT_call_all_calls.
 */
public final class GhidraCallSiteEvidence {
    public enum Kind {
        ORDINARY, DIRECT_CALL, INDIRECT_CALL, INTERNAL_BRANCH,
        DIRECT_TAIL_CANDIDATE, INDIRECT_TAIL_CANDIDATE, THUNK_TRANSFER,
        RETURN, UNAVAILABLE
    }
    public record Range(Address first, Address last) { }
    public record Operand(Address address, int bytes) { }
    public record Operation(int opcode, Operand output, List<Operand> inputs) {
        public Operation { inputs = List.copyOf(inputs); }
    }
    public record Callee(Address entry, String name, boolean external, boolean thunk,
            Address thunkTarget, boolean noReturn, String convention, String callFixup) { }
    public record Transfer(Kind kind, Address target, Address returnPc, Callee callee, String reason) { }
    public record InstructionEvidence(Address address, Address end, String bytes, String assembly,
            String context, String flow, String defaultFlow, String override,
            List<Address> targets, List<Address> defaultTargets, Address fallThrough,
            List<Operation> operations, ElfCodeBytes.Match original, Transfer transfer) {
        public InstructionEvidence {
            targets = List.copyOf(targets);
            defaultTargets = List.copyOf(defaultTargets);
            operations = List.copyOf(operations);
        }
    }
    public record FunctionEvidence(Callee function, List<Range> body,
            List<InstructionEvidence> instructions, List<String> omissions) {
        public FunctionEvidence {
            body = List.copyOf(body);
            instructions = List.copyOf(instructions);
            omissions = List.copyOf(omissions);
        }
        /** Inventory completeness only; never a call-site emission/completeness proof. */
        public boolean captureComplete() { return omissions.isEmpty(); }
    }

    private GhidraCallSiteEvidence() { }

    /** Caller must hold a consistent Program view and preserve the input identity until publication. */
    public static List<FunctionEvidence> capture(Program program, List<Function> functions,
            ElfImage image, long rebaseDelta, TaskMonitor monitor) throws IOException, CancelledException {
        monitor.checkCancelled();
        GhidraTargetAgreement.requireAgreement(program, image);
        BooleanSupplier cancelled = () -> {
            try { monitor.checkCancelled(); return false; }
            catch (CancelledException cancellation) { return true; }
        };
        try {
            var effects = ElfRelocationEffects.inspect(image, cancelled);
            var result = new ArrayList<FunctionEvidence>();
            try (var original = ElfCodeBytes.open(image, cancelled)) {
                for (Function function : functions) {
                    monitor.checkCancelled();
                    if (function.getProgram() != program) throw new IllegalArgumentException("foreign program function");
                    result.add(captureFunction(program, function, original, effects, rebaseDelta, monitor, cancelled));
                }
            }
            monitor.checkCancelled();
            return List.copyOf(result);
        }
        catch (CancellationException cancellation) { throw new CancelledException(); }
    }

    private static FunctionEvidence captureFunction(Program program, Function function, ElfCodeBytes original,
            ElfRelocationEffects effects, long delta, TaskMonitor monitor, BooleanSupplier cancelled)
            throws IOException, CancelledException {
        var identity = identity(function);
        var body = new AddressSet(function.getBody());
        var ranges = new ArrayList<Range>();
        for (var range : body.getAddressRanges(true)) {
            monitor.checkCancelled();
            ranges.add(new Range(range.getMinAddress(), range.getMaxAddress()));
        }
        var instructions = new ArrayList<InstructionEvidence>();
        var omissions = new ArrayList<String>();
        if (function.isExternal() || body.isEmpty() || body.getNumAddresses() > 1_048_576) {
            return new FunctionEvidence(identity, ranges, List.of(), List.of("external, empty or unbounded function body"));
        }
        var covered = new AddressSet();
        for (var instruction : program.getListing().getInstructions(body, true)) {
            monitor.checkCancelled();
            if (instructions.size() >= 65_536) {
                omissions.add("instruction capture budget exceeded");
                break;
            }
            InstructionEvidence evidence = captureInstruction(program, identity, body, instruction,
                original, effects, delta, monitor, cancelled);
            instructions.add(evidence);
            if (evidence.transfer().kind() == Kind.UNAVAILABLE) {
                omissions.add(evidence.address() + ": " + evidence.transfer().reason());
            }
            covered.add(instruction.getAddress(), instruction.getMaxAddress());
        }
        if (!covered.equals(body) || program.getListing().getInstructionAt(function.getEntryPoint()) == null) {
            omissions.add("function has partial or undecoded instruction coverage");
        }
        var starts = new java.util.HashSet<Address>();
        for (var instruction : instructions) starts.add(instruction.address());
        for (var instruction : instructions) {
            monitor.checkCancelled();
            if (instruction.fallThrough() != null && !starts.contains(instruction.fallThrough())) {
                omissions.add(instruction.address() + ": fallthrough escapes the decoded body");
            }
            if (instruction.transfer().kind() == Kind.INTERNAL_BRANCH && !starts.contains(instruction.transfer().target())) {
                omissions.add(instruction.address() + ": internal branch targets an undecoded instruction boundary");
            }
        }
        if (!body.equals(function.getBody()) || !identity.equals(identity(function))) {
            omissions.add("function changed during call-site capture");
        }
        monitor.checkCancelled();
        return new FunctionEvidence(identity, ranges, instructions, omissions);
    }

    /** Validate one incoming transfer without asserting an owning function/body inventory. */
    static Transfer incomingTransfer(Program program, Instruction instruction, ElfCodeBytes original,
            ElfRelocationEffects effects, long delta, TaskMonitor monitor, BooleanSupplier cancelled)
            throws IOException, CancelledException {
        return captureInstruction(program, null,
            new AddressSet(instruction.getAddress(), instruction.getMaxAddress()), instruction,
            original, effects, delta, monitor, cancelled).transfer();
    }

    private static InstructionEvidence captureInstruction(Program program, Callee caller, AddressSet body,
            Instruction instruction, ElfCodeBytes original, ElfRelocationEffects effects, long delta,
            TaskMonitor monitor, BooleanSupplier cancelled) throws IOException, CancelledException {
        Address address = instruction.getAddress();
        FlowType flow = instruction.getFlowType();
        FlowType decoded = instruction.getPrototype().getFlowType(instruction.getInstructionContext());
        List<Address> targets = addresses(instruction.getFlows());
        List<Address> defaults = addresses(instruction.getDefaultFlows());
        var operations = new ArrayList<Operation>();
        var raw = instruction.getPcode(false);
        String bytes = "";
        String problem = "";
        ElfCodeBytes.Match match = null;
        if (raw == null || raw.length > 4096) {
            problem = "missing or unbounded raw p-code";
        }
        else {
            for (var operation : raw) {
                monitor.checkCancelled();
                var inputs = new ArrayList<Operand>();
                for (var node : operation.getInputs()) inputs.add(operand(node));
                operations.add(new Operation(operation.getOpcode(), operand(operation.getOutput()), inputs));
            }
        }
        try {
            require(problem.isEmpty(), problem);
            require(address.isMemoryAddress() && !address.getAddressSpace().isOverlaySpace() &&
                address.getAddressSpace().equals(program.getAddressFactory().getDefaultAddressSpace()), "unsupported instruction address space");
            require(body.contains(address, instruction.getMaxAddress()) && instruction.getLength() > 0 &&
                instruction.getLength() == instruction.getParsedLength() && !instruction.isLengthOverridden(), "partial or overridden instruction length");
            // Ghidra's analyzer commonly adds CALL_RETURN to tail-shaped jumps.
            // Retain that annotation, but classify the original branch, never its
            // synthetic p-code CALL/RETURN. This exception grants no tail proof.
            boolean annotatedJump = instruction.getFlowOverride() == FlowOverride.CALL_RETURN &&
                decoded.isJump() && !decoded.isConditional() && !decoded.hasFallthrough() &&
                flow.isCall() && flow.isTerminal() && !flow.hasFallthrough();
            // Resolved references on a computed transfer are hints, not decoded
            // targets. Keep them in the observation, but never use them as origins.
            boolean computedHints = decoded.isComputed() && defaults.isEmpty();
            require((instruction.getFlowOverride() == FlowOverride.NONE && flow.equals(decoded) || annotatedJump) &&
                !instruction.isFallThroughOverridden() && (targets.equals(defaults) || computedHints),
                "listing control flow differs from raw decode");
            require(instruction.getDelaySlotDepth() == 0 && !instruction.isInDelaySlot(), "delayed transfer requires a separate return-address proof");
            require(Objects.equals(instruction.getFallThrough(), instruction.getDefaultFallThrough()), "fallthrough differs from raw decode");
            byte[] parsed = instruction.getParsedBytes();
            bytes = HexFormat.of().formatHex(parsed);
            byte[] live = new byte[parsed.length];
            require(parsed.length == instruction.getLength() && program.getMemory().getBytes(address, live) == live.length &&
                Arrays.equals(parsed, live), "instruction bytes changed after decoding");
            long normalized = AddressNormalizer.toElfAddress(address.getOffset(), delta);
            effects.requireUnchanged(normalized, parsed.length, cancelled);
            match = original.requireMatches(normalized, parsed, cancelled);
        }
        catch (IllegalArgumentException | ArithmeticException | ghidra.program.model.mem.MemoryAccessException unavailable) {
            problem = unavailable.getMessage();
        }
        Transfer transfer;
        try {
            require(problem.isEmpty(), problem);
            transfer = classify(program, caller, body, instruction, decoded, defaults, operations);
        }
        catch (IllegalArgumentException unavailable) {
            transfer = new Transfer(Kind.UNAVAILABLE, null, null, null, unavailable.getMessage());
        }
        var contextRegister = program.getProgramContext().getBaseContextRegister();
        var context = contextRegister == null ? null : instruction.getRegisterValue(contextRegister);
        return new InstructionEvidence(address, instruction.getMaxAddress(), bytes, instruction.toString(),
            String.valueOf(context), flow.toString(), decoded.toString(), instruction.getFlowOverride().name(),
            targets, defaults, instruction.getFallThrough(), operations, match, transfer);
    }

    private static Transfer classify(Program program, Callee caller, AddressSet body, Instruction instruction,
            FlowType flow, List<Address> targets, List<Operation> operations) {
        boolean thunk = caller != null && caller.thunk();
        var transfers = new ArrayList<Operation>();
        for (var operation : operations) {
            int opcode = operation.opcode();
            require(opcode != PcodeOp.CALLOTHER && opcode != PcodeOp.UNIMPLEMENTED, "opaque instruction effects");
            if (opcode == PcodeOp.CALL || opcode == PcodeOp.CALLIND || opcode == PcodeOp.RETURN ||
                    opcode == PcodeOp.BRANCHIND || opcode == PcodeOp.BRANCH || opcode == PcodeOp.CBRANCH) {
                // A constant p-code branch stays within the instruction; it is not a machine call/branch.
                if ((opcode == PcodeOp.BRANCH || opcode == PcodeOp.CBRANCH) && !operation.inputs().isEmpty() &&
                        operation.inputs().getFirst().address().isConstantAddress()) continue;
                // Conditional moves can skip their remaining effects by branching
                // to the decoded next instruction. Preserve that raw operation for
                // value analysis, but do not invent a machine-level call/branch.
                if ((opcode == PcodeOp.BRANCH || opcode == PcodeOp.CBRANCH) && flow.isFallthrough() &&
                        !flow.isJump() && !flow.isCall() && !operation.inputs().isEmpty() &&
                        operation.inputs().getFirst().address().equals(instruction.getDefaultFallThrough())) continue;
                transfers.add(operation);
            }
        }
        if (flow.isFallthrough() && !flow.isCall() && !flow.isJump() && !flow.isTerminal()) {
            require(transfers.isEmpty(), "raw transfer contradicts fallthrough flow");
            return new Transfer(Kind.ORDINARY, null, null, null, "");
        }
        require(transfers.size() == 1, "no unique raw machine transfer");
        var transfer = transfers.getFirst();
        require(transfer.output() == null && !transfer.inputs().isEmpty(), "malformed raw transfer");
        int opcode = transfer.opcode();
        if (flow.isCall()) {
            require(!flow.isConditional() && flow.hasFallthrough() && transfer.inputs().size() == 1 &&
                operations.getLast() == transfer && Objects.equals(instruction.getFallThrough(), instruction.getMaxAddress().next()),
                "call lacks an ordinary decoded return address");
            require(operations.stream().noneMatch(operation -> operation.opcode() == PcodeOp.BRANCH ||
                operation.opcode() == PcodeOp.CBRANCH), "call has unproved intra-instruction control flow");
            if (opcode == PcodeOp.CALLIND) {
                require(flow.isComputed() && targets.isEmpty(), "indirect call has contradictory direct targets");
                return new Transfer(Kind.INDIRECT_CALL, null, instruction.getFallThrough(), null, "unresolved indirect target");
            }
            require(opcode == PcodeOp.CALL && !flow.isComputed(), "raw call kind differs from listing");
            Address target = directTarget(instruction, targets, transfer);
            return new Transfer(Kind.DIRECT_CALL, target, instruction.getFallThrough(), callee(program, target), "");
        }
        if (opcode == PcodeOp.RETURN) {
            require(flow.isTerminal() && !flow.hasFallthrough() && targets.isEmpty(), "raw return differs from listing");
            return new Transfer(Kind.RETURN, null, null, null, "");
        }
        require(flow.isJump(), "non-call raw transfer lacks jump flow");
        if (opcode == PcodeOp.BRANCHIND) {
            require(flow.isComputed() && !flow.hasFallthrough() && targets.isEmpty(), "computed branch has unproved target references");
            return new Transfer(thunk ? Kind.THUNK_TRANSFER : Kind.INDIRECT_TAIL_CANDIDATE,
                null, null, null, "indirect jump may be internal; target and tail semantics remain unproved");
        }
        require((opcode == PcodeOp.BRANCH || opcode == PcodeOp.CBRANCH) && !flow.isComputed(), "raw jump kind differs from listing");
        require((opcode == PcodeOp.CBRANCH) == flow.isConditional(), "branch condition differs from listing");
        Address target = directTarget(instruction, targets, transfer);
        Callee callee = callee(program, target);
        Kind kind = body.contains(target) ? Kind.INTERNAL_BRANCH : thunk ? Kind.THUNK_TRANSFER : Kind.DIRECT_TAIL_CANDIDATE;
        return new Transfer(kind, target, null, callee, kind == Kind.INTERNAL_BRANCH ? "" :
            "external branch requires exact callee and return/stack-state proofs");
    }

    private static Address directTarget(Instruction instruction, List<Address> targets, Operation transfer) {
        require(targets.size() == 1 && targets.getFirst().equals(transfer.inputs().getFirst().address()) &&
            targets.getFirst().getAddressSpace().equals(instruction.getAddress().getAddressSpace()), "raw and decoded targets disagree");
        return targets.getFirst();
    }
    private static Callee callee(Program program, Address target) {
        var function = program.getFunctionManager().getFunctionAt(target);
        return function == null ? null : identity(function);
    }
    private static Callee identity(Function function) {
        var target = function.getThunkedFunction(false);
        return new Callee(function.getEntryPoint(), function.getName(), function.isExternal(), function.isThunk(),
            target == null ? null : target.getEntryPoint(), function.hasNoReturn(), function.getCallingConventionName(), function.getCallFixup());
    }
    private static Operand operand(Varnode node) { return node == null ? null : new Operand(node.getAddress(), node.getSize()); }
    private static List<Address> addresses(Address[] addresses) { return addresses == null ? List.of() : List.of(addresses); }
    private static void require(boolean test, String reason) { if (!test) throw new IllegalArgumentException(reason); }
}
