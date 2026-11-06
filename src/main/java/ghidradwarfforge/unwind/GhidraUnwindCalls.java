package ghidradwarfforge.unwind;

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.nio.ByteOrder;
import java.io.IOException;
import java.util.HexFormat;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.elf.ElfCodeBytes;
import ghidradwarfforge.AddressNormalizer;
import ghidradwarfforge.targets.UnwindAbiProfile;
import ghidradwarfforge.unwind.UnwindCalls.*;
import ghidradwarfforge.unwind.UnwindFlow.*;

/** Native direct-call closure; no external/indirect callee contract is assumed. */
public final class GhidraUnwindCalls {
    public record Evidence(UnwindAbiProfile.Bound profile, ByteOrder byteOrder, Verified<Address> verified,
            Map<Address, GhidraUnwindInstructions.Captured> captures, Map<Address, ElfCodeBytes.Match> originalBytes) {
        public Evidence {
            captures = Collections.unmodifiableMap(new LinkedHashMap<>(captures));
            originalBytes = Collections.unmodifiableMap(new LinkedHashMap<>(originalBytes));
        }
    }
    private GhidraUnwindCalls() { }

    /** Caller must hold a consistent program view and retain input identity through final publication. */
    public static Evidence verify(Program program, Function root, ElfImage image, long rebaseDelta, TaskMonitor monitor)
            throws CancelledException, IOException {
        if (root.getProgram() != program) throw new IllegalArgumentException("function belongs to another program");
        var profile = UnwindAbiProfile.select(program, root, image, rebaseDelta, monitor);
        var preserved = new LinkedHashMap<Cell, Incoming>();
        for (Cell cell : profile.calleeSavedCells()) preserved.put(cell, (Incoming) profile.entry().values().get(cell));
        var contract = new Contract(profile.entry(), profile.stackPointer(), profile.programCounter(), preserved,
            profile.description().returnStackAdjustment());
        var pending = new ArrayDeque<Function>();
        var discovered = new LinkedHashSet<Address>();
        var bodies = new LinkedHashMap<Address, Body<Address>>();
        var captures = new LinkedHashMap<Address, GhidraUnwindInstructions.Captured>();
        pending.add(root);
        discovered.add(root.getEntryPoint());
        int totalNodes = 0;
        while (!pending.isEmpty()) {
            monitor.checkCancelled();
            Function function = pending.removeFirst();
            var selected = UnwindAbiProfile.select(program, function, image, rebaseDelta, monitor);
            if (!selected.equals(profile)) throw new IllegalArgumentException("callee profile differs from caller");
            var targets = new LinkedHashMap<Address, Address>();
            var captured = GhidraUnwindInstructions.capture(program, function, selected::requireInstruction, instruction -> {
                monitor.checkCancelled();
                Address target = directTarget(instruction);
                Function callee = program.getFunctionManager().getFunctionAt(target);
                if (callee == null) throw new IllegalArgumentException("direct callee entry is not a known function");
                targets.put(instruction.getAddress(), target);
                if (discovered.add(target)) {
                    if (discovered.size() > 1024) throw new IllegalArgumentException("native callee closure budget exceeded");
                    pending.add(callee);
                }
                return new Call(preserved.keySet(), contract.returnAdjustment(), 0L, "native direct-call hypothesis; not verified");
            }, monitor);
            totalNodes = Math.addExact(totalNodes, captured.graph().size());
            if (totalNodes > 65_536) throw new IllegalArgumentException("native callee instruction budget exceeded");
            var bindings = new LinkedHashMap<Site<Address>, Address>();
            var returns = new LinkedHashSet<Address>();
            for (var item : captured.graph().entrySet()) {
                monitor.checkCancelled();
                Address address = item.getKey();
                var node = item.getValue();
                for (int index = 0; index < node.effects().size(); index++) {
                    if (node.effects().get(index) instanceof Call) {
                        Address target = targets.get(address);
                        if (target == null) throw new IllegalArgumentException("lowered call lost its decoded target");
                        bindings.put(new Site<>(address, index), target);
                    }
                }
                if (node.successors().isEmpty()) {
                    Instruction instruction = program.getListing().getInstructionAt(address);
                    if (!instruction.getFlowType().isTerminal() ||
                            Arrays.stream(instruction.getPcode()).filter(op -> op.getOpcode() == PcodeOp.RETURN).count() != 1) {
                        throw new IllegalArgumentException("terminal instruction is not an ordinary decoded return");
                    }
                    returns.add(address);
                }
            }
            bodies.put(function.getEntryPoint(), new Body<>(function.getEntryPoint(), captured.graph(), bindings, returns));
            captures.put(function.getEntryPoint(), captured);
        }
        try {
            java.util.function.BooleanSupplier cancelled = () -> {
                try { monitor.checkCancelled(); return false; }
                catch (CancelledException failure) { return true; }
            };
            var originalBytes = new LinkedHashMap<Address, ElfCodeBytes.Match>();
            try (var original = ElfCodeBytes.open(image, cancelled)) {
                for (var captured : captures.values()) {
                    for (var instruction : captured.observations().entrySet()) {
                        monitor.checkCancelled();
                        long normalized = AddressNormalizer.toElfAddress(instruction.getKey().getOffset(), rebaseDelta);
                        originalBytes.put(instruction.getKey(), original.requireMatches(normalized,
                            HexFormat.of().parseHex(instruction.getValue().bytes()), cancelled));
                    }
                }
            }
            var verified = UnwindCalls.verify(bodies, contract, cancelled);
            monitor.checkCancelled();
            return new Evidence(profile, image.byteOrder(), verified, captures, originalBytes);
        }
        catch (CancellationException cancelled) { throw new CancelledException(); }
    }

    private static Address directTarget(Instruction instruction) {
        if (!instruction.getFlowType().isCall() || instruction.getFlowType().isComputed() ||
                !instruction.getFlowType().hasFallthrough() || instruction.getFlows().length != 1) {
            throw new IllegalArgumentException("callee target is not one direct returning call");
        }
        var calls = Arrays.stream(instruction.getPcode()).filter(op ->
            op.getOpcode() == PcodeOp.CALL || op.getOpcode() == PcodeOp.CALLIND).toList();
        Address target = instruction.getFlows()[0];
        if (calls.size() != 1 || calls.getFirst().getOpcode() != PcodeOp.CALL ||
                !target.equals(calls.getFirst().getInput(0).getAddress())) {
            throw new IllegalArgumentException("decoded and p-code call targets disagree");
        }
        return target;
    }
}
