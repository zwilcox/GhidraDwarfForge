package ghidradwarfforge.unwind;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CancellationException;

import ghidra.program.model.address.Address;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.AddressNormalizer;
import ghidradwarfforge.unwind.CallFramePlan.*;

/** Address-preserving evidence to original-image frame ranges; not an exporter entry point. */
public final class GhidraUnwindFrames {
    public record Observation(Address function, Address instruction, int length, UnwindFrameRows.Projected projection) { }
    public record Planned(CallFramePlan plan, List<Observation> observations, UnwindStackSeparation separation) {
        public Planned { observations = List.copyOf(observations); java.util.Objects.requireNonNull(separation); }
    }
    private GhidraUnwindFrames() { }

    public static Planned plan(GhidraUnwindCalls.Evidence evidence, long rebaseDelta, TaskMonitor monitor)
            throws CancelledException {
        monitor.checkCancelled();
        if (evidence.verified().separation().conditional()) {
            throw new IllegalArgumentException("conditional stack separation requires an explicit qualified projection path");
        }
        return planInternal(evidence, rebaseDelta, monitor);
    }

    /** Caller explicitly accepts the exact external condition; it remains attached to the projection. */
    public static Planned planConditioned(GhidraUnwindCalls.Evidence evidence, long rebaseDelta,
            TaskMonitor monitor, UnwindStackSeparation accepted) throws CancelledException {
        monitor.checkCancelled();
        if (!accepted.conditional() || !accepted.equals(evidence.verified().separation())) {
            throw new IllegalArgumentException("conditional projection requires the exact accepted separation condition");
        }
        return planInternal(evidence, rebaseDelta, monitor);
    }

    private static Planned planInternal(GhidraUnwindCalls.Evidence evidence, long rebaseDelta, TaskMonitor monitor)
            throws CancelledException {
        var profile = evidence.profile();
        var description = profile.description();
        var policy = new UnwindFrameRows.Policy(profile.registers(), description.stackNumber(),
            description.returnNumber(), description.counterNumber(), description.entryCfaOffset(), description.returnStackAdjustment());
        var frames = new ArrayList<Frame>();
        var observations = new ArrayList<Observation>();
        var functions = new TreeMap<>(evidence.verified().bodies());
        for (var function : functions.entrySet()) {
            monitor.checkCancelled();
            var captured = evidence.captures().get(function.getKey());
            var flow = evidence.verified().flows().get(function.getKey());
            var instructions = new TreeMap<>(captured.observations());
            var rows = new ArrayList<Row>();
            long start = 0, size = 0;
            Address previousEnd = null;
            for (var instruction : instructions.entrySet()) {
                monitor.checkCancelled();
                Address address = instruction.getKey();
                int length = instruction.getValue().bytes().length() / 2;
                if (length < 1 || (instruction.getValue().bytes().length() & 1) != 0) {
                    throw new IllegalArgumentException("invalid captured instruction extent");
                }
                boolean call = function.getValue().graph().get(address).effects().stream()
                    .anyMatch(effect -> effect instanceof UnwindFlow.Call);
                long normalized = AddressNormalizer.toElfAddress(address.getOffset(), rebaseDelta);
                var projected = evidence.originalCoverage().overlaps(normalized, length) ?
                    new UnwindFrameRows.Projected(null, Map.of(), Map.of(), "original frame coverage takes precedence") :
                    project(flow.before().get(address), call ? flow.after().get(address) : null, policy, monitor);
                observations.add(new Observation(function.getKey(), address, length, projected));
                boolean adjacent = previousEnd != null && address.equals(previousEnd.next());
                if (!projected.covered() || !adjacent) {
                    if (!rows.isEmpty()) frames.add(new Frame(start, size, rows));
                    rows = new ArrayList<>(); size = 0;
                }
                previousEnd = null;
                if (!projected.covered()) continue;
                if (rows.isEmpty()) start = normalized;
                size = Math.addExact(size, length);
                rows.add(new Row(normalized, projected.cfa(), projected.rules()));
                try { previousEnd = address.addNoWrap(length - 1); }
                catch (ghidra.program.model.address.AddressOverflowException overflow) {
                    throw new IllegalArgumentException("captured instruction wraps address space", overflow);
                }
            }
            if (!rows.isEmpty()) frames.add(new Frame(start, size, rows));
        }
        var initial = project(profile.entry(), null, policy, monitor);
        if (!initial.covered()) throw new IllegalArgumentException("profile has no complete initial frame rules");
        monitor.checkCancelled();
        return new Planned(new CallFramePlan(profile.stackPointer().bytes(), evidence.byteOrder(),
            description.returnNumber(), profile.registers().keySet(), initial.rules(), frames), observations, evidence.verified().separation());
    }

    private static UnwindFrameRows.Projected project(UnwindFlow.State state, UnwindFlow.State after,
            UnwindFrameRows.Policy policy, TaskMonitor monitor)
            throws CancelledException {
        try {
            java.util.function.BooleanSupplier cancelled = () -> {
                try { monitor.checkCancelled(); return false; }
                catch (CancelledException failure) { return true; }
            };
            return after == null ? UnwindFrameRows.project(state, policy, cancelled) :
                UnwindFrameRows.projectCall(state, after, policy, cancelled);
        }
        catch (CancellationException cancelled) { throw new CancelledException(); }
    }
}
