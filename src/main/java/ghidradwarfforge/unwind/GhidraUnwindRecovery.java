package ghidradwarfforge.unwind;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.elf.ElfCodeBytes;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.unwind.CallFramePlan.Frame;

/** Collect independently proved call groups without turning one refusal into a program-wide failure. */
public final class GhidraUnwindRecovery {
    private static final int MAX_FUNCTIONS = 65536;
    private static final int MAX_INSTRUCTIONS = 1_000_000;

    public record Recovered(Optional<CallFramePlan> plan, Set<Address> verifiedFunctions,
            Map<Address, GhidraUnwindFrames.Observation> observations,
            Map<Address, ElfCodeBytes.Match> originalBytes, Map<Address, String> refusals) {
        public Recovered {
            verifiedFunctions = Collections.unmodifiableSet(new TreeSet<>(verifiedFunctions));
            observations = Collections.unmodifiableMap(new TreeMap<>(observations));
            originalBytes = Collections.unmodifiableMap(new TreeMap<>(originalBytes));
            refusals = Collections.unmodifiableMap(new TreeMap<>(refusals));
        }
    }

    private GhidraUnwindRecovery() { }

    /**
     * Caller must hold a consistent program view and protect input identity through
     * publication. This collects evidence; it does not enable exporter synthesis.
     * Unsupported roots are recorded individually. I/O, cancellation, conflicting
     * evidence and whole-program budgets abort without returning a partial plan.
     */
    public static Recovered recover(Program program, ElfImage image, long rebaseDelta, TaskMonitor monitor)
            throws IOException, CancelledException {
        monitor.checkCancelled();
        var verified = new TreeSet<Address>();
        var observations = new TreeMap<Address, GhidraUnwindFrames.Observation>();
        var originalBytes = new TreeMap<Address, ElfCodeBytes.Match>();
        var refusals = new TreeMap<Address, String>();
        var frames = new TreeMap<Long, Frame>(Long::compareUnsigned);
        CallFramePlan template = null;
        int roots = 0;
        var functions = program.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            monitor.checkCancelled();
            var function = functions.next();
            if (++roots > MAX_FUNCTIONS) throw new IllegalArgumentException("program unwind function budget exceeded");
            if (verified.contains(function.getEntryPoint())) continue;
            GhidraUnwindCalls.Evidence evidence;
            GhidraUnwindFrames.Planned planned;
            try {
                evidence = GhidraUnwindCalls.verify(program, function, image, rebaseDelta, monitor);
                planned = GhidraUnwindFrames.plan(evidence, rebaseDelta, monitor);
            }
            catch (IllegalArgumentException unsupported) {
                monitor.checkCancelled();
                refusals.put(function.getEntryPoint(), unsupported.getMessage());
                continue;
            }
            var plan = planned.plan();
            if (template == null) template = plan;
            else if (template.addressBytes() != plan.addressBytes() || template.order() != plan.order() ||
                    template.returnRegister() != plan.returnRegister() || !template.registers().equals(plan.registers()) ||
                    !template.initialRules().equals(plan.initialRules())) {
                throw new IOException("inconsistent unwind profiles across proved call groups");
            }
            for (var observation : planned.observations()) {
                monitor.checkCancelled();
                requireSame(observations, observation.instruction(), observation);
                if (observations.size() > MAX_INSTRUCTIONS) {
                    throw new IllegalArgumentException("program unwind instruction budget exceeded");
                }
            }
            for (var entry : evidence.originalBytes().entrySet()) {
                monitor.checkCancelled();
                requireSame(originalBytes, entry.getKey(), entry.getValue());
            }
            for (var frame : plan.frames()) {
                monitor.checkCancelled();
                requireSame(frames, frame.address(), frame);
                if (frames.size() > CallFramePlan.MAX_FRAMES) throw new IllegalArgumentException("program unwind frame budget exceeded");
            }
            for (var address : evidence.verified().bodies().keySet()) {
                monitor.checkCancelled();
                if (refusals.containsKey(address)) throw new IOException("a previously refused unwind function changed its evidence");
                verified.add(address);
            }
        }
        Frame previous = null;
        for (var frame : frames.values()) {
            monitor.checkCancelled();
            if (previous != null && Long.compareUnsigned(previous.address() + previous.size() - 1, frame.address()) >= 0) {
                throw new IOException("proved unwind groups contain overlapping frame ranges");
            }
            previous = frame;
        }
        if (!observations.keySet().equals(originalBytes.keySet())) throw new IOException("unwind collection lost original byte evidence");
        monitor.checkCancelled();
        Optional<CallFramePlan> result = template == null ? Optional.empty() : Optional.of(new CallFramePlan(
            template.addressBytes(), template.order(), template.returnRegister(), template.registers(),
            template.initialRules(), List.copyOf(frames.values())));
        return new Recovered(result, verified, observations, originalBytes, refusals);
    }

    private static <K, V> void requireSame(Map<K, V> values, K key, V value) throws IOException {
        V previous = values.putIfAbsent(key, value);
        if (previous != null && !previous.equals(value)) throw new IOException("conflicting repeated unwind evidence at " + key);
    }
}
