package ghidradwarfforge.calls;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.LinkedHashSet;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.calls.GhidraCallSiteEvidence.*;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.elf.ElfCodeBytes;
import ghidradwarfforge.elf.ElfRelocationEffects;
import ghidradwarfforge.targets.UnwindAbiProfile;
import ghidradwarfforge.unwind.GhidraUnwindInstructions;
import ghidradwarfforge.unwind.UnwindFlow;
import ghidradwarfforge.unwind.UnwindFlow.*;

/**
 * Proves entry-compatible state at direct tail transfers. No caller history,
 * actual argument, all-call-sites flag or callee preservation summary is inferred.
 * Unresolved graph edges reject the function rather than disappearing at a cut.
 */
public final class GhidraTailStateProof {
    public record Tail(Address caller, Address instruction, Address callee, String profile,
            State state, String originalInstructionSha256) { }
    public record Result(List<FunctionEvidence> captures, List<Tail> tails, Map<Address, String> omissions,
            Map<Address, GhidraBoundedSwitch.Proof> switches) {
        public Result {
            captures = List.copyOf(captures);
            tails = List.copyOf(tails);
            omissions = Collections.unmodifiableMap(new LinkedHashMap<>(omissions));
            switches = Collections.unmodifiableMap(new LinkedHashMap<>(switches));
        }
    }
    private GhidraTailStateProof() { }

    /** Caller holds a consistent Program view and preserves original identity through publication. */
    public static Result verify(Program program, List<Function> functions, ElfImage image, long delta,
            TaskMonitor monitor) throws IOException, CancelledException {
        var captures = GhidraCallSiteEvidence.capture(program, functions, image, delta, monitor);
        var tails = new ArrayList<Tail>();
        var omissions = new LinkedHashMap<Address, String>();
        var switches = new LinkedHashMap<Address, GhidraBoundedSwitch.Proof>();
        BooleanSupplier cancelled = () -> {
            try { monitor.checkCancelled(); return false; }
            catch (CancelledException cancellation) { return true; }
        };
        try {
            for (var capture : captures) {
                monitor.checkCancelled();
                if (capture.instructions().stream().noneMatch(item -> candidate(item.transfer().kind()))) continue;
                try {
                    var dispatches = switches(program, capture, image, delta, monitor);
                    tails.addAll(verifyFunction(program, capture, dispatches, image, delta, monitor, cancelled));
                    switches.putAll(dispatches);
                }
                catch (IllegalArgumentException unavailable) {
                    omissions.put(capture.function().entry(), unavailable.getMessage());
                }
            }
            // A split cold block can have a Function label yet inherit another
            // function's active frame. Do not seed an ordinary entry contract
            // across a known non-call edge unless that edge has itself passed
            // the boundary proof. Iterate so a rejected predecessor invalidates
            // downstream proofs rather than leaving a self-supporting chain.
            var dependencies = new LinkedHashMap<Address, List<Address>>();
            try (var original = ElfCodeBytes.open(image, cancelled)) {
                var effects = ElfRelocationEffects.inspect(image, cancelled);
                for (var capture : captures) {
                    monitor.checkCancelled();
                    // Ordinary outgoing calls also consume entry-value facts.
                    // A label reached with another function's active frame must
                    // not gain such facts just because it has no outgoing tail.
                    if (omissions.containsKey(capture.function().entry())) continue;
                    try {
                        dependencies.put(capture.function().entry(), incomingBranches(program, capture,
                            original, effects, delta, monitor, cancelled));
                    }
                    catch (IllegalArgumentException unavailable) {
                        omissions.put(capture.function().entry(), unavailable.getMessage());
                        tails.removeIf(tail -> tail.caller().equals(capture.function().entry()));
                    }
                }
            }
            boolean changed;
            do {
                monitor.checkCancelled();
                changed = false;
                var admitted = new LinkedHashMap<Address, Address>();
                for (var tail : tails) admitted.put(tail.instruction(), tail.callee());
                var rejected = new LinkedHashSet<Address>();
                for (var entry : dependencies.entrySet()) {
                    monitor.checkCancelled();
                    for (Address incoming : entry.getValue()) {
                        monitor.checkCancelled();
                        if (!entry.getKey().equals(admitted.get(incoming))) {
                            rejected.add(entry.getKey());
                            omissions.put(entry.getKey(), "entry has an unproved incoming non-call transfer at " + incoming);
                            break;
                        }
                    }
                }
                if (!rejected.isEmpty()) {
                    changed = tails.removeIf(tail -> rejected.contains(tail.caller()));
                    rejected.forEach(dependencies::remove);
                }
            } while (changed);
        }
        catch (CancellationException cancellation) { throw new CancelledException(); }
        monitor.checkCancelled();
        return new Result(captures, tails, omissions, switches);
    }

    private static Map<Address, GhidraBoundedSwitch.Proof> switches(Program program, FunctionEvidence capture,
            ElfImage image, long delta, TaskMonitor monitor) throws IOException, CancelledException {
        var result = new LinkedHashMap<Address, GhidraBoundedSwitch.Proof>();
        if (!capture.captureComplete()) return result;
        var starts = new LinkedHashSet<Address>();
        capture.instructions().forEach(i -> starts.add(i.address()));
        int candidates = 0;
        for (var instruction : capture.instructions()) {
            monitor.checkCancelled();
            if (instruction.transfer().kind() != Kind.INDIRECT_TAIL_CANDIDATE ||
                    instruction.operations().isEmpty() || instruction.operations().getLast().opcode() != PcodeOp.BRANCHIND) continue;
            require(++candidates <= 64, "bounded switch candidate budget exceeded");
            var next = program.getListing().getInstructionAt(instruction.address());
            for (int count = 0; count < 32; count++) {
                monitor.checkCancelled();
                var previous = program.getListing().getInstructionBefore(next.getAddress());
                if (previous == null || !starts.contains(previous.getAddress()) ||
                        !next.getAddress().equals(previous.getDefaultFallThrough())) break;
                if (previous.getPrototype().getFlowType(previous.getInstructionContext()).isConditional()) {
                    var comparison = program.getListing().getInstructionBefore(previous.getAddress());
                    if (comparison == null || !starts.contains(comparison.getAddress())) break;
                    try {
                        var proof = GhidraBoundedSwitch.prove(program, comparison, image, delta, monitor);
                        require(proof.transfer().equals(instruction.address()) && starts.containsAll(proof.targets()),
                            "computed target is outside the captured caller body");
                        result.put(instruction.address(), proof);
                    }
                    catch (IllegalArgumentException unavailable) { /* Leave the original unresolved-transfer omission. */ }
                    break;
                }
                if (!previous.getPrototype().getFlowType(previous.getInstructionContext()).isFallthrough()) break;
                next = previous;
            }
        }
        return result;
    }

    private static List<Address> incomingBranches(Program program, FunctionEvidence capture, ElfCodeBytes original,
            ElfRelocationEffects effects, long delta, TaskMonitor monitor, BooleanSupplier cancelled)
            throws IOException, CancelledException {
        var function = program.getFunctionManager().getFunctionAt(capture.function().entry());
        var body = function.getBody();
        var dependencies = new LinkedHashSet<Address>();
        for (var range : body) {
            monitor.checkCancelled();
            var previous = program.getListing().getInstructionBefore(range.getMinAddress());
            require(previous == null || body.contains(previous.getAddress()) ||
                !range.getMinAddress().equals(previous.getDefaultFallThrough()), "body has an external fallthrough entry");
        }
        var destinations = program.getReferenceManager().getReferenceDestinationIterator(body, true);
        int references = 0;
        while (destinations.hasNext()) {
            monitor.checkCancelled();
            Address destination = destinations.next();
            for (var reference : program.getReferenceManager().getReferencesTo(destination)) {
                monitor.checkCancelled();
                require(++references <= 65_536, "incoming-reference budget exceeded");
                // Symbol entry markers and pointer-data indirections are not
                // executable incoming edges (nor evidence that an edge is safe).
                if (reference.isEntryPointReference() || reference.getReferenceType().isIndirect() ||
                        !reference.getReferenceType().isFlow() ||
                        body.contains(reference.getFromAddress())) continue;
                require(destination.equals(function.getEntryPoint()), "body has an external interior control-flow entry");
                var instruction = program.getListing().getInstructionAt(reference.getFromAddress());
                require(instruction != null, "incoming flow lacks a decoded instruction: " + reference);
                var transfer = GhidraCallSiteEvidence.incomingTransfer(program, instruction, original,
                    effects, delta, monitor, cancelled);
                require(transfer.kind() != Kind.UNAVAILABLE, "incoming instruction lacks original transfer evidence: " + transfer.reason());
                boolean ordinaryCall = transfer.kind() == Kind.DIRECT_CALL && destination.equals(transfer.target());
                // In particular CALL_RETURN annotations on raw branches are not
                // ordinary calls. Computed-reference hints cannot discharge this.
                if (!ordinaryCall) dependencies.add(instruction.getAddress());
            }
        }
        return List.copyOf(dependencies);
    }

    private static List<Tail> verifyFunction(Program program, FunctionEvidence capture,
            Map<Address, GhidraBoundedSwitch.Proof> switches, ElfImage image, long delta,
            TaskMonitor monitor, BooleanSupplier cancelled) throws CancelledException {
        require(capture.captureComplete(), "incomplete instruction inventory: " + String.join("; ", capture.omissions()));
        Function function = program.getFunctionManager().getFunctionAt(capture.function().entry());
        require(function != null, "caller identity disappeared");
        var profile = UnwindAbiProfile.selectForCallSites(program, function, image, delta, monitor);
        var graph = new LinkedHashMap<Address, Node<Address>>();
        var candidates = new ArrayList<InstructionEvidence>();
        for (var instruction : capture.instructions()) {
            monitor.checkCancelled();
            var transfer = instruction.transfer();
            require(transfer.kind() != Kind.UNAVAILABLE, "unavailable instruction semantics");
            var nativeInstruction = program.getListing().getInstructionAt(instruction.address());
            require(nativeInstruction != null, "captured instruction disappeared");
            profile.requireInstruction(nativeInstruction, monitor);
            if (candidate(transfer.kind()) && !switches.containsKey(instruction.address())) {
                // A computed jump may re-enter any body node. Never model an
                // unresolved branch as a terminal merely to make a proof pass.
                require(transfer.target() != null && transfer.callee() != null && !transfer.callee().external(),
                    "external branch lacks a decoded exact callee entry");
                var callee = program.getFunctionManager().getFunctionAt(transfer.target());
                require(callee != null, "callee identity disappeared");
                var targetProfile = UnwindAbiProfile.selectForCallSites(program, callee, image, delta, monitor);
                require(profile.description().equals(targetProfile.description()), "tail transfer changes the admitted ABI");
                var last = instruction.operations().getLast();
                require((last.opcode() == PcodeOp.BRANCH || last.opcode() == PcodeOp.CBRANCH) &&
                    last.inputs().getFirst().address().equals(transfer.target()), "tail transfer has trailing or unproved effects");
                candidates.add(instruction);
            }
            var successors = new ArrayList<Address>();
            if (instruction.fallThrough() != null) successors.add(instruction.fallThrough());
            if (transfer.kind() == Kind.INTERNAL_BRANCH && !successors.contains(transfer.target())) successors.add(transfer.target());
            var dispatch = switches.get(instruction.address());
            if (dispatch != null) for (Address target : dispatch.targets()) if (!successors.contains(target)) successors.add(target);
            graph.put(instruction.address(), new Node<>(
                dispatch == null ? GhidraUnwindInstructions.callSiteEffects(program, nativeInstruction, monitor) :
                    List.of(new Opaque("bounded dispatch does not preserve frame-state facts")), successors));
        }
        var flow = UnwindFlow.analyze(graph, capture.function().entry(), profile.entry(), profile.stackPointer(), cancelled);
        var result = new ArrayList<Tail>();
        // Every external branch must establish the boundary state. Otherwise an
        // unproved outgoing edge could be a non-call continuation back into the body.
        for (var instruction : candidates) {
            monitor.checkCancelled();
            State state = flow.after().get(instruction.address());
            require(state != null, "tail candidate has no proved reachable state");
            require(new StackAddress(0, profile.stackPointer().bytes()).equals(state.values().get(profile.stackPointer())),
                "tail transfer does not restore the entry stack pointer at " + instruction.address());
            Value returned = profile.description().stackReturn() ?
                state.memory().get(new Slot(0, profile.stackPointer().bytes())) :
                state.values().get(profile.registers().get(profile.description().returnNumber()));
            require(new ReturnAddress(profile.stackPointer().bytes()).equals(returned),
                "tail transfer loses the original return destination at " + instruction.address());
            for (Cell preserved : profile.calleeSavedCells()) {
                monitor.checkCancelled();
                require(profile.entry().values().get(preserved).equals(state.values().get(preserved)),
                    "tail transfer does not restore a callee-saved register at " + instruction.address());
            }
            result.add(new Tail(capture.function().entry(), instruction.address(), instruction.transfer().target(),
                profile.description().id(), state, instruction.original().sha256()));
        }
        return List.copyOf(result);
    }

    private static boolean candidate(Kind kind) {
        return kind == Kind.DIRECT_TAIL_CANDIDATE || kind == Kind.INDIRECT_TAIL_CANDIDATE || kind == Kind.THUNK_TRANSFER;
    }
    private static void require(boolean value, String reason) { if (!value) throw new IllegalArgumentException(reason); }
}
