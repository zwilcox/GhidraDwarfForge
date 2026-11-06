// Read-only instruction context checks against saved fixture state and native listing APIs.
// @category DWARF.Tests
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.GhidraInstructionContext;
import ghidradwarfforge.GhidraInstructionContext.Budget;
import ghidradwarfforge.GhidraInstructionContext.Limits;
import ghidradwarfforge.source.SourceContextMode;
import com.google.gson.GsonBuilder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public class VerifyInstructionContext extends GhidraScript {
    private static final class Probe extends TaskMonitorAdapter {
        int checks;
        final int stop;
        Probe(int stop) { this.stop = stop; }
        @Override public void checkCancelled() throws CancelledException {
            if (++checks == stop) throw new CancelledException();
        }
    }

    private void require(boolean ok, String message) { if (!ok) throw new AssertionError(message); }
    private void store(String key, Address address) { currentProgram.getOptions("ForgeContextTest").setString(key, address.toString()); }
    private Address address(String key) { return currentProgram.getAddressFactory().getAddress(currentProgram.getOptions("ForgeContextTest").getString(key, "")); }
    private Function owner(Address address) { return currentProgram.getFunctionManager().getFunctionContaining(address); }

    private void setup() throws Exception {
        analyzeAll(currentProgram);
        Instruction split = null, removed = null, truncated = null, call = null;
        for (var iterator = currentProgram.getListing().getInstructions(true); iterator.hasNext();) {
            var item = iterator.next();
            Function function = owner(item.getAddress());
            if (function == null || function.isThunk()) continue;
            var next = currentProgram.getListing().getInstructionAfter(item.getAddress());
            var later = next == null ? null : currentProgram.getListing().getInstructionAfter(next.getAddress());
            if (split == null && next != null && later != null && function.getBody().contains(later.getMaxAddress()) &&
                    item.getMaxAddress().next().equals(next.getAddress()) && next.getMaxAddress().next().equals(later.getAddress()) &&
                    !item.getFlowType().isCall() && !next.isInDelaySlot() && next.getDelaySlotDepth() == 0) {
                split = item;
                removed = next;
            }
            if (truncated == null && item.getParsedLength() > 1 && !item.getFlowType().isCall() &&
                    !item.isInDelaySlot() && item.getDelaySlotDepth() == 0 &&
                    (split == null || !function.equals(owner(split.getAddress())))) truncated = item;
            if (call == null && item.getFlowType().isCall() && item.getFlowOverride() == FlowOverride.NONE &&
                    Arrays.stream(item.getPcode(false)).anyMatch(op -> op.getOpcode() == PcodeOp.CALL ||
                        op.getOpcode() == PcodeOp.CALLIND) &&
                    (split == null || !function.equals(owner(split.getAddress())))) call = item;
        }
        require(split != null && removed != null && truncated != null && call != null, "fixture controls unavailable");
        Function splitFunction = owner(split.getAddress());
        var body = new AddressSet(splitFunction.getBody());
        body.delete(removed.getMinAddress(), removed.getMaxAddress());
        splitFunction.setBody(body);
        store("split", split.getAddress());
        store("gap", removed.getAddress());
        int alignment = currentProgram.getLanguage().getInstructionAlignment();
        String truncatedStatus;
        if (alignment < truncated.getParsedLength()) {
            truncated.setLengthOverride(alignment);
            require(truncated.getLength() == alignment && truncated.getParsedLength() > alignment,
                "partial listing fixture not established");
            truncatedStatus = "INCOMPLETE_PARSED_BYTES";
        }
        else {
            var truncatedBody = new AddressSet(owner(truncated.getAddress()).getBody());
            truncatedBody.delete(truncated.getMinAddress().add(1), truncated.getMaxAddress());
            owner(truncated.getAddress()).setBody(truncatedBody);
            truncatedStatus = "BODY_RANGE_END";
        }
        currentProgram.getOptions("ForgeContextTest").setString("truncatedStatus", truncatedStatus);
        store("truncated", truncated.getAddress());
        call.setFlowOverride(FlowOverride.BRANCH);
        store("override", call.getAddress());
        for (int index = 0; index < 3; index++) {
            String key = new String[] {"unmapped", "uninitialized", "undecoded"}[index];
            Address start = toAddr(0x70010000L + index * 0x1000L);
            require(!currentProgram.getMemory().contains(start), "context test address occupied");
            int size = index == 2 ? 5 : 8;
            if (index == 1) currentProgram.getMemory().createUninitializedBlock("CONTEXT_" + key, start, size, false);
            if (index == 2) currentProgram.getMemory().createInitializedBlock("CONTEXT_" + key, start, size, (byte) 0x5a, monitor, false);
            currentProgram.getFunctionManager().createFunction("CONTEXT_" + key, start,
                new AddressSet(start, start.add(size - 1)), SourceType.USER_DEFINED);
            store(key, start);
        }
    }

    private List<Object> operations(List<GhidraInstructionContext.Operation> input) {
        var rows = new ArrayList<Object>();
        for (var op : input) {
            var row = new TreeMap<String, Object>();
            row.put("address", op.address().toString(true)); row.put("sequence", op.sequence());
            row.put("mnemonic", op.mnemonic()); row.put("output", op.output()); row.put("inputs", op.inputs());
            rows.add(row);
        }
        return rows;
    }

    private List<Object> expected(PcodeOp[] input, int limit, ghidra.program.model.address.AddressRange range) {
        var rows = new ArrayList<Object>();
        for (int index = 0; index < Math.min(input.length, limit); index++) {
            var op = input[index];
            if (!range.contains(op.getSeqnum().getTarget())) continue;
            var row = new TreeMap<String, Object>();
            row.put("address", op.getSeqnum().getTarget().toString(true)); row.put("sequence", op.getSeqnum().getTime());
            row.put("mnemonic", op.getMnemonic()); row.put("output", op.getOutput() == null ? null : op.getOutput().toString());
            row.put("inputs", Arrays.stream(op.getInputs()).limit(64).map(Object::toString).toList());
            rows.add(row);
        }
        return rows;
    }

    private Object verify(String key) throws Exception {
        Address focus = address(key);
        Function function = owner(focus);
        var budget = new Budget(function, Limits.DEFAULT);
        var probe = new Probe(-1);
        var result = GhidraInstructionContext.read(currentProgram, function, focus, SourceContextMode.BOTH, budget, probe);
        var range = function.getBody().getRangeContaining(focus);
        var rows = new ArrayList<Object>();
        for (var observed : result.instructions()) {
            var row = new TreeMap<String, Object>();
            row.put("address", observed.start().toString(true)); row.put("end", observed.listingEnd() == null ? null : observed.listingEnd().toString(true));
            row.put("length", observed.listingLength()); row.put("parsedLength", observed.parsedLength());
            row.put("bytes", java.util.HexFormat.of().formatHex(observed.bytes())); row.put("status", observed.byteStatus());
            row.put("assembly", observed.assembly()); row.put("context", observed.context());
            row.put("inDelaySlot", observed.inDelaySlot()); row.put("delaySlotDepth", observed.delaySlotDepth());
            row.put("flowOverride", observed.flowOverride()); row.put("raw", operations(observed.pcode().raw()));
            row.put("effective", operations(observed.pcode().effective())); row.put("pcodeDiagnostics", observed.pcode().diagnostics());
            for (int offset = 0; offset < observed.bytes().length; offset++) {
                require(range.contains(observed.start().add(offset)), "bytes crossed body gap");
                require(observed.bytes()[offset] == currentProgram.getMemory().getByte(observed.start().add(offset)), "memory bytes changed");
            }
            if (observed.bytes().length != 0) {
                byte[] copy = observed.bytes(); byte first = copy[0]; copy[0] ^= 1;
                require(observed.bytes()[0] == first, "mutable snapshot bytes");
            }
            var instruction = currentProgram.getListing().getInstructionAt(observed.start());
            if (observed.byteStatus().equals("COMPLETE")) {
                require(instruction != null && instruction.toString().equals(observed.assembly()), "assembly was not listing evidence");
                require(range.contains(observed.listingEnd()), "instruction crossed body gap");
                var raw = instruction.getPcode(false);
                require(expected(raw, 64, range).equals(row.get("raw")), "raw instruction pcode differs");
                int remaining = Math.max(0, 64 - raw.length);
                require(expected(remaining == 0 ? new PcodeOp[0] : instruction.getPcode(true), remaining, range).equals(row.get("effective")), "effective instruction pcode differs");
                require(observed.inDelaySlot() == instruction.isInDelaySlot() && observed.delaySlotDepth() == instruction.getDelaySlotDepth(), "delay ownership lost");
            }
            else require(observed.assembly() == null && observed.pcode().raw().isEmpty() && observed.pcode().effective().isEmpty(), "incomplete bytes invented semantics");
            var base = currentProgram.getProgramContext().getBaseContextRegister();
            if (base != null) {
                var value = currentProgram.getProgramContext().getRegisterValue(base, observed.start());
                require(observed.context().name().equals(base.getName()) && observed.context().bits() == base.getBitLength(), "context register lost");
                require(java.util.Objects.equals(observed.context().mask(), value == null ? null : value.getValueMask().toString(16)), "context mask lost");
                require(java.util.Objects.equals(observed.context().value(), value == null ? null : value.getUnsignedValueIgnoreMask().toString(16)), "context value lost");
            }
            rows.add(row);
        }
        require(budget.bytes() <= 64 && budget.instructions() <= 3, "trigger budget exceeded");
        for (int stop = 1; stop <= probe.checks; stop++) {
            try {
                GhidraInstructionContext.read(currentProgram, function, focus, SourceContextMode.BOTH, new Budget(function, Limits.DEFAULT), new Probe(stop));
                throw new AssertionError("context cancellation ignored at " + stop);
            }
            catch (CancelledException expected) { }
        }
        var off = new Budget(function, Limits.DEFAULT);
        require(GhidraInstructionContext.read(currentProgram, function, focus, SourceContextMode.OFF, off, monitor).instructions().isEmpty() && off.bytes() == 0 && off.instructions() == 0, "off consumed context");
        if (key.equals("override")) {
            var focusObservation = result.instructions().getFirst();
            require(focusObservation.flowOverride().equals("BRANCH"), "saved override was changed after curation");
            require(!operations(focusObservation.pcode().raw()).equals(operations(focusObservation.pcode().effective())),
                "override does not distinguish pcode variants: " + focusObservation);
            var repeated = GhidraInstructionContext.read(currentProgram, function, focus, SourceContextMode.BOTH, budget, monitor);
            require(repeated.instructions().isEmpty() && repeated.reused().contains(focus), "repeated context was copied");
            var limited = GhidraInstructionContext.read(currentProgram, function, focus, SourceContextMode.BOTH, new Budget(function, new Limits(1, 64, 64, 1)), monitor);
            var item = limited.instructions().getFirst();
            require(item.pcode().raw().size() + item.pcode().effective().size() <= 1 && !item.pcode().diagnostics().isEmpty(), "shared pcode limit ignored");
            var bytes = GhidraInstructionContext.read(currentProgram, function, focus, SourceContextMode.BOTH, new Budget(function, new Limits(16, 1, 1, 64)), monitor);
            require(bytes.instructions().getFirst().bytes().length == 1 && bytes.instructions().getFirst().assembly() == null, "byte limit invented instruction");
            for (var mode : List.of(SourceContextMode.ASSEMBLY, SourceContextMode.PCODE)) {
                var selected = GhidraInstructionContext.read(currentProgram, function, focus, mode, new Budget(function, Limits.DEFAULT), monitor).instructions().getFirst();
                require((selected.assembly() != null) == mode.assembly(), "assembly mode differs");
                require(selected.pcode().raw().isEmpty() != mode.pcode(), "pcode mode differs");
            }
        }
        if (key.equals("split")) {
            require(!range.contains(address("gap")) && result.instructions().size() == 1, "context bridged discontiguous body");
            var outside = GhidraInstructionContext.read(currentProgram, function, address("gap"), SourceContextMode.BOTH, new Budget(function, Limits.DEFAULT), monitor);
            require(outside.instructions().isEmpty() && outside.diagnostics().equals(List.of("FOCUS_OUTSIDE_FUNCTION_BODY")), "outside body was interpreted");
        }
        if (key.equals("truncated")) require(result.instructions().getFirst().byteStatus().equals(
            currentProgram.getOptions("ForgeContextTest").getString("truncatedStatus", "")), "partial instruction not retained");
        if (key.equals("undecoded")) require(result.instructions().getFirst().bytes().length == 5, "available undecoded bytes missing");
        if (key.equals("unmapped") || key.equals("uninitialized")) require(result.instructions().getFirst().bytes().length == 0, "unavailable memory invented");
        var row = new TreeMap<String, Object>();
        row.put("focus", focus.toString(true)); row.put("function", function.getName());
        row.put("rangeStart", result.rangeStart().toString(true)); row.put("rangeEnd", result.rangeEnd().toString(true));
        row.put("instructions", rows); row.put("diagnostics", result.diagnostics()); row.put("cancellationPoints", probe.checks);
        return row;
    }

    @Override protected void run() throws Exception {
        if (getScriptArgs()[0].equals("setup")) setup();
        var result = new TreeMap<String, Object>();
        for (String key : List.of("split", "truncated", "override", "unmapped", "uninitialized", "undecoded")) result.put(key, verify(key));
        result.put("language", currentProgram.getLanguageID().toString());
        result.put("compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        result.put("origin", GhidraInstructionContext.class.getProtectionDomain().getCodeSource().getLocation().toString());
        Files.writeString(Path.of(getScriptArgs()[1]), new GsonBuilder().serializeNulls().setPrettyPrinting().create().toJson(result) + "\n");
        println("instruction-context=PASS");
    }
}
