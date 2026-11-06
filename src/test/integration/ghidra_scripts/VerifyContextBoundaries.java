// Exercise native delay-slot folding and actual mixed ARM/Thumb context at body boundaries.
// @category DWARF.Tests
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.task.TaskMonitorAdapter;
import ghidra.util.exception.CancelledException;
import ghidradwarfforge.GhidraInstructionContext;
import ghidradwarfforge.GhidraFunctionSymbols;
import ghidradwarfforge.GhidraSourceContext;
import ghidradwarfforge.GhidraSyntheticSource;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter;
import ghidradwarfforge.source.SourceContextMode;
import java.nio.file.Files;
import java.nio.file.Path;
import java.math.BigInteger;
import java.util.List;
import java.util.TreeMap;
import java.util.ArrayList;
import com.google.gson.GsonBuilder;

public class VerifyContextBoundaries extends GhidraScript {
    private void require(boolean value, String message) { if (!value) throw new AssertionError(message); }
    private static final class Probe extends TaskMonitorAdapter {
        int checks;
        final int stop;
        Probe(int stop) { this.stop = stop; }
        @Override public void checkCancelled() throws CancelledException {
            if (++checks == stop) throw new CancelledException();
        }
    }

    private Object observe(Function function, long offset, GhidraInstructionContext.Limits limits,
            boolean completePcode, String expectedDiagnostic) throws Exception {
        var focus = function.getEntryPoint().add(offset);
        var probe = new Probe(-1);
        var snapshot = GhidraInstructionContext.read(currentProgram, function, focus, SourceContextMode.BOTH,
            new GhidraInstructionContext.Budget(function, limits), probe);
        var first = snapshot.instructions().getFirst();
        require(first.byteStatus().equals("COMPLETE") && first.assembly() != null, "focus bytes/assembly lost");
        require(!first.pcode().raw().isEmpty() == completePcode && !first.pcode().effective().isEmpty() == completePcode,
            "delay-slot p-code eligibility differs: " + snapshot);
        if (expectedDiagnostic != null) require(first.pcode().diagnostics().contains(expectedDiagnostic), "omission reason missing");
        var rows = new ArrayList<Object>();
        for (var item : snapshot.instructions()) {
            var instruction = getInstructionAt(item.start());
            var base = currentProgram.getProgramContext().getBaseContextRegister();
            var context = currentProgram.getProgramContext().getRegisterValue(base, item.start());
            require(item.context().mask().equals(context.getValueMask().toString(16)) &&
                item.context().value().equals(context.getUnsignedValueIgnoreMask().toString(16)), "context differs from program database");
            for (int index = 0; index < item.bytes().length; index++) {
                require(function.getBody().getRangeContaining(focus).contains(item.start().add(index)), "bytes crossed body gap");
                require(item.bytes()[index] == currentProgram.getMemory().getByte(item.start().add(index)), "bytes fabricated");
            }
            require(item.inDelaySlot() == instruction.isInDelaySlot() &&
                item.delaySlotDepth() == instruction.getDelaySlotDepth(), "delay ownership lost");
            var row = new TreeMap<String, Object>();
            row.put("address", item.start().getOffset()); row.put("bytes", java.util.HexFormat.of().formatHex(item.bytes()));
            row.put("status", item.byteStatus()); row.put("assembly", item.assembly()); row.put("context", item.context());
            row.put("inDelaySlot", item.inDelaySlot()); row.put("delaySlotDepth", item.delaySlotDepth());
            row.put("raw", item.pcode().raw().stream().map(op -> op.address() + ":" + op.mnemonic() + ":" + op.output() + ":" + op.inputs()).toList());
            row.put("effective", item.pcode().effective().stream().map(op -> op.address() + ":" + op.mnemonic() + ":" + op.output() + ":" + op.inputs()).toList());
            row.put("diagnostics", item.pcode().diagnostics()); rows.add(row);
        }
        for (int stop = 1; stop <= probe.checks; stop++) {
            try {
                GhidraInstructionContext.read(currentProgram, function, focus, SourceContextMode.BOTH,
                    new GhidraInstructionContext.Budget(function, limits), new Probe(stop));
                throw new AssertionError("cancellation ignored at " + stop);
            }
            catch (CancelledException expected) { }
        }
        return new TreeMap<>(java.util.Map.of("focus", focus.getOffset(), "instructions", rows,
            "cancellationPoints", probe.checks, "diagnostics", snapshot.diagnostics()));
    }

    private void export(Function function, Path output, Path consumer, Path producer) throws Exception {
        var functions = GhidraFunctionSymbols.extract(currentProgram, monitor, ignored -> {}, 0).stream()
            .filter(symbol -> symbol.name().equals(function.getName())).toList();
        require(functions.size() == 1, "selected function missing");
        var context = new GhidraSourceContext(currentProgram, SourceContextMode.BOTH, GhidraSourceContext.Limits.DEFAULT);
        var source = GhidraSyntheticSource.decompileDetailed(currentProgram, functions, 0, monitor,
            (decompiler, selected, timeout, taskMonitor) -> {
                var options = new DecompileOptions(); options.setMaxInstructions(1);
                require(decompiler.setOptions(options), "native limit rejected");
                var result = decompiler.decompileFunction(selected, timeout, taskMonitor);
                require(!result.decompileCompleted() && result.getErrorMessage().contains("maximum allowable instructions"),
                    "expected genuine native instruction-limit failure: " + result.getErrorMessage());
                context.accept(selected, result, taskMonitor);
                return result;
            }).source();
        var diagnostic = context.compose(source, 0, 4 * 1024 * 1024, monitor);
        require(diagnostic.mappedLines().isEmpty(), "failed diagnostic source invented executable rows");
        diagnostic.writeAtomically(Path.of(output + ".c"));
        new MinimalDwarfSidecarExporter().export(Path.of(currentProgram.getExecutablePath()), output, consumer, producer,
            functions, diagnostic);
    }

    @Override protected void run() throws Exception {
        String[] args = getScriptArgs();
        require(args.length == 4, "target output-directory consumer producer");
        boolean arm = args[0].equals("arm32");
        Path output = Path.of(args[1]); Files.createDirectories(output);
        var function = getGlobalFunctions(arm ? "recovered_mixed_body" : "delay_context").getFirst();
        var body = new AddressSet(function.getBody());
        var entry = function.getEntryPoint();
        byte[] bytes = getBytes(entry, arm ? 52 : 20);
        var observations = new TreeMap<String, Object>();
        try {
            if (arm) {
                var mode = currentProgram.getRegister("TMode");
                for (long offset : new long[] {0, 8, 24, 32}) {
                    int expected = offset == 24 ? 1 : 0;
                    require(BigInteger.valueOf(expected).equals(currentProgram.getProgramContext().getValue(mode, entry.add(offset), false)),
                        "expected actual ARM/Thumb context");
                    observations.put("mode-" + offset, observe(function, offset, GhidraInstructionContext.Limits.DEFAULT, true, null));
                }
                require(!body.contains(entry.add(4)), "ARM literal gap control missing");
                export(function, output.resolve("full.dbg"), Path.of(args[2]), Path.of(args[3]));
            }
            else {
                var branch = getInstructionAt(entry);
                var slot = getInstructionAt(entry.add(4));
                require(branch.getDelaySlotDepth() == 1 && slot.isInDelaySlot(), "delay fixture was not decoded");
                require(java.util.Arrays.stream(branch.getPcode(false)).anyMatch(op -> op.getOpcode() == PcodeOp.INT_ADD &&
                    op.getSeqnum().getTarget().equals(entry) && op.getInput(1).isConstant() && op.getInput(1).getOffset() == 9),
                    "native delay-slot effect was not folded under branch address");
                observations.put("full", observe(function, 0, GhidraInstructionContext.Limits.DEFAULT, true, null));
                observations.put("bytes", observe(function, 0, new GhidraInstructionContext.Limits(16, 4, 4, 64), false,
                    "DELAY_SLOT_BYTES_NOT_OBSERVED"));
                observations.put("instructions", observe(function, 0, new GhidraInstructionContext.Limits(1, 64, 64, 64), false,
                    "DELAY_SLOT_BYTES_NOT_OBSERVED"));
                export(function, output.resolve("full.dbg"), Path.of(args[2]), Path.of(args[3]));
                var split = new AddressSet(body); split.delete(slot.getMinAddress(), slot.getMaxAddress()); function.setBody(split);
                observations.put("gap", observe(function, 0, GhidraInstructionContext.Limits.DEFAULT, false,
                    "DELAY_SLOT_OUTSIDE_SELECTED_BODY_RANGE"));
                export(function, output.resolve("gap.dbg"), Path.of(args[2]), Path.of(args[3]));
                var partial = new AddressSet(body); partial.delete(entry.add(6), entry.add(7)); function.setBody(partial);
                observations.put("partial", observe(function, 0, GhidraInstructionContext.Limits.DEFAULT, false,
                    "INCOMPLETE_DELAY_SLOT_CONTEXT"));
                export(function, output.resolve("partial.dbg"), Path.of(args[2]), Path.of(args[3]));
            }
        }
        finally { function.setBody(body); }
        require(java.util.Arrays.equals(bytes, getBytes(entry, bytes.length)), "original bytes changed");
        require(function.getBody().hasSameAddresses(body), "function body restoration failed");
        observations.put("entry", entry.getOffset()); observations.put("target", args[0]);
        observations.put("origin", GhidraInstructionContext.class.getProtectionDomain().getCodeSource().getLocation().toString());
        Files.writeString(output.resolve("observations.json"), new GsonBuilder().setPrettyPrinting().create().toJson(observations) + "\n");
        println("context-boundaries=PASS");
    }
}
