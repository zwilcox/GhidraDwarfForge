package ghidradwarfforge.calls;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.AddressNormalizer;
import ghidradwarfforge.GhidraCallParameters;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.targets.UnwindAbiProfile;
import ghidradwarfforge.types.ProgramTypeModel;

/** Composes original-instruction proofs into normalized writer input. */
public final class GhidraCallSitePlan {
    public record Result(CallSitePlan plan, ProgramTypeModel types, Map<Long, List<String>> diagnostics) {
        public Result {
            var copy = new LinkedHashMap<Long, List<String>>();
            diagnostics.forEach((address, reasons) -> copy.put(address, List.copyOf(reasons)));
            diagnostics = Collections.unmodifiableMap(copy);
        }
    }
    private GhidraCallSitePlan() { }

    /** Caller retains a consistent Program/input view through final publication. */
    public static Result recover(Program program, List<FunctionSymbol> symbols, ProgramTypeModel types,
            List<GhidraCallParameters.Entry> entries, TargetRegisterMap registers, ElfImage image,
            long delta, TaskMonitor monitor) throws IOException, CancelledException {
        monitor.checkCancelled();
        var diagnostics = new LinkedHashMap<Long, List<String>>();
        var exported = new LinkedHashMap<Long, FunctionSymbol>();
        var selected = new ArrayList<Function>();
        var space = program.getAddressFactory().getDefaultAddressSpace();
        for (var symbol : symbols) {
            monitor.checkCancelled();
            if (exported.put(symbol.address(), symbol) != null) throw new IllegalArgumentException("duplicate exported function entry");
            var function = program.getFunctionManager().getFunctionAt(space.getAddress(Math.addExact(symbol.address(), delta)));
            if (function == null) {
                note(diagnostics, symbol.address(), "no exact Ghidra function entry");
                continue;
            }
            try {
                // Select before opening the ELF instruction/relocation analysis:
                // other target profiles retain their existing export behavior.
                UnwindAbiProfile.selectForCallSites(program, function, image, delta, monitor);
                selected.add(function);
            }
            catch (IllegalArgumentException unavailable) { note(diagnostics, symbol.address(), unavailable.getMessage()); }
        }
        // Value-flow states are keyed by instruction address. Reject shared
        // ownership before analysis, so one caller cannot overwrite another's
        // entry-dependent state or acquire its call-site return lookup key.
        var seen = new AddressSet();
        var shared = new AddressSet();
        for (var function : selected) {
            monitor.checkCancelled();
            shared.add(seen.intersect(function.getBody()));
            seen.add(function.getBody());
        }
        var exclusive = new ArrayList<Function>();
        for (var function : selected) {
            monitor.checkCancelled();
            if (shared.intersects(function.getBody())) {
                note(diagnostics, normalize(function.getEntryPoint(), delta), "function body overlaps another selected caller");
            }
            else exclusive.add(function);
        }
        if (exclusive.isEmpty()) return new Result(CallSitePlan.EMPTY, types, diagnostics);
        final GhidraTailStateProof.Result proof;
        try { proof = GhidraTailStateProof.verify(program, exclusive, image, delta, monitor); }
        catch (IllegalArgumentException unavailable) {
            // A valid original may use loader metadata outside the audited
            // instruction-write profile. Omit this feature without losing its
            // existing symbols/types/source; I/O errors and cancellation escape.
            for (var function : exclusive) {
                monitor.checkCancelled();
                note(diagnostics, normalize(function.getEntryPoint(), delta), "call-site capture unavailable: " + unavailable.getMessage());
            }
            return new Result(CallSitePlan.EMPTY, types, diagnostics);
        }
        var values = GhidraCallArgumentFlow.analyze(program, proof, image, delta, monitor);
        var tails = new LinkedHashMap<Address, GhidraTailStateProof.Tail>();
        for (var tail : proof.tails()) tails.put(tail.instruction(), tail);
        var signatures = new LinkedHashMap<Long, ProgramTypeModel.FunctionSignature>();
        if (types != null) for (var signature : types.functions()) signatures.put(signature.address(), signature);
        var byFunction = new LinkedHashMap<Long, List<GhidraCallParameters.Entry>>();
        for (var entry : entries) {
            monitor.checkCancelled();
            byFunction.computeIfAbsent(entry.functionId(), ignored -> new ArrayList<>()).add(entry);
        }
        var functions = new ArrayList<CallSitePlan.FunctionCalls>();
        for (var capture : proof.captures()) {
            monitor.checkCancelled();
            Address entry = capture.function().entry();
            long owner = normalize(entry, delta);
            var reasons = new ArrayList<>(capture.omissions());
            if (proof.omissions().containsKey(entry)) reasons.add(proof.omissions().get(entry));
            if (values.omissions().containsKey(entry)) reasons.add(values.omissions().get(entry));
            var sites = new ArrayList<CallSitePlan.Site>();
            for (var instruction : capture.instructions()) {
                monitor.checkCancelled();
                var transfer = instruction.transfer();
                boolean tail = tails.containsKey(instruction.address());
                boolean call = transfer.kind() == GhidraCallSiteEvidence.Kind.DIRECT_CALL ||
                    transfer.kind() == GhidraCallSiteEvidence.Kind.INDIRECT_CALL;
                if (!call && !tail) {
                    if (proof.switches().containsKey(instruction.address())) continue;
                    switch (transfer.kind()) {
                        case DIRECT_TAIL_CANDIDATE, INDIRECT_TAIL_CANDIDATE, THUNK_TRANSFER, UNAVAILABLE ->
                            reasons.add(instruction.address() + ": transfer has no admitted call-site proof");
                        default -> { }
                    }
                    continue;
                }
                long instructionAddress = normalize(instruction.address(), delta);
                // No delay slots are admitted by capture. The tail key follows
                // the instruction for GDB lookup; it is not a runtime return address.
                Address continuation = tail ? instruction.end().next() : transfer.returnPc();
                if (continuation == null || normalize(continuation, delta) <= instructionAddress ||
                        exported.get(owner).ranges().stream().noneMatch(range -> range.contains(instructionAddress))) {
                    reasons.add(instruction.address() + ": unrepresentable call-site owner or return key");
                    continue;
                }
                Long origin = transfer.callee() == null || transfer.callee().external() ? null : normalize(transfer.callee().entry(), delta);
                if (origin != null && !exported.containsKey(origin)) {
                    note(diagnostics, owner, instruction.address() + ": callee is not exported; origin omitted");
                    origin = null;
                }
                List<CallSitePlan.Argument> arguments = List.of();
                if (origin != null && types != null) {
                    var callee = program.getFunctionManager().getFunctionAt(transfer.callee().entry());
                    if (callee == null) throw new IllegalArgumentException("captured callee disappeared");
                    var bound = GhidraCallParameters.bind(program, callee, signatures.get(origin), types.types(),
                        byFunction.getOrDefault(callee.getID(), List.of()), values.transfers().get(instruction.address()),
                        registers, image, delta, monitor);
                    arguments = bound.arguments();
                    for (String omission : bound.omissions()) note(diagnostics, owner, instruction.address() + ": " + omission);
                }
                sites.add(new CallSitePlan.Site(instructionAddress, normalize(continuation, delta), tail, origin, arguments));
            }
            // Successful value-flow analysis includes a closed, decoded graph,
            // audited instruction semantics and a valid known entry contract.
            // Parameter omissions do not make the call inventory incomplete.
            var completeness = reasons.isEmpty() ? CallSitePlan.Completeness.ALL_CALLS : CallSitePlan.Completeness.PARTIAL;
            reasons.forEach(reason -> note(diagnostics, owner, reason));
            functions.add(new CallSitePlan.FunctionCalls(owner, completeness, sites));
        }
        var plan = new CallSitePlan(functions);
        plan.validate(symbols, types, image.is64Bit() ? 8 : 4);
        monitor.checkCancelled();
        var entryTypes = GhidraCallParameters.withEntryLocations(program, types, entries, proof.captures(),
            registers, image, delta, monitor);
        return new Result(plan, entryTypes, diagnostics);
    }

    private static long normalize(Address address, long delta) {
        return AddressNormalizer.toElfAddress(address.getOffset(), delta);
    }
    private static void note(Map<Long, List<String>> diagnostics, long address, String reason) {
        diagnostics.computeIfAbsent(address, ignored -> new ArrayList<>()).add(reason);
    }
}
