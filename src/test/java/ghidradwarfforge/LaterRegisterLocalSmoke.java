package ghidradwarfforge;

import java.io.File;
import java.util.HexFormat;
import java.util.List;

import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariable;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.Storage;

/** Actual decoder controls for curated later register locals, not lexical-scope inference. */
public final class LaterRegisterLocalSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (String target : List.of("x86_64", "aarch64")) {
            for (int width : new int[] { 4, 8 }) {
                check(target, width);
            }
        }
        System.out.println("later-register-local-smoke=PASS checks=" + checks);
    }

    private static void check(String target, int width) throws Exception {
        boolean x86 = target.equals("x86_64");
        var language = DefaultLanguageService.getLanguageService().getLanguage(
            new LanguageID(x86 ? "x86:LE:64:default" : "AARCH64:LE:64:v8A"));
        String hex = x86 ? (width == 4 ? "448d57074489d04531d29090909090c3" : "4c8d57074c89d04531d29090909090c3") :
            (width == 4 ? "091c0011e003092ae9031faa1f2003d5c0035fd6" :
                "091c0091e00309aae9031faa1f2003d5c0035fd6");
        byte[] bytes = HexFormat.of().parseHex(hex);
        Object owner = new Object();
        var program = new ProgramDB("local", language, language.getDefaultCompilerSpec(), owner);
        try {
            int transaction = program.startTransaction("later local model");
            try {
                var entry = language.getDefaultSpace().getAddress(0x1000);
                var body = new AddressSet(entry, entry.add(bytes.length - 1));
                var block = program.getMemory().createInitializedBlock("code", entry, bytes.length,
                    (byte) 0, TaskMonitor.DUMMY, false);
                block.setExecute(true);
                program.getMemory().setBytes(entry, bytes);
                require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY), "decode");
                Function function = program.getFunctionManager().createFunction("local", entry, body, SourceType.USER_DEFINED);
                var type = width == 4 ? IntegerDataType.dataType : LongLongDataType.dataType;
                var register = program.getRegister(x86 ? (width == 4 ? "R10D" : "R10") : (width == 4 ? "w9" : "x9"));
                LocalVariable local = (LocalVariable) function.addLocalVariable(new LocalVariableImpl(
                    "held", 4, type, register, program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
                var mapping = TargetRegisterMap.forTarget(target);
                Storage rejected = GhidraVariableStorage.stableLocal(program, function, local, mapping, TaskMonitor.DUMMY);
                var intervals = GhidraVariableStorage.localPrefix(program, function, local, mapping, rejected, TaskMonitor.DUMMY);
                long boundary = entry.getOffset() + (x86 ? 10 : 12);
                require(intervals.size() == 3 && intervals.get(0).start() == 0x1000 &&
                    intervals.get(0).end() == 0x1004 && !intervals.get(0).storage().available() &&
                    intervals.get(1).start() == 0x1004 && intervals.get(1).end() == boundary &&
                    intervals.get(1).storage().available() && intervals.get(2).start() == boundary &&
                    intervals.get(2).end() == 0x1000 + bytes.length && !intervals.get(2).storage().available(),
                    "wrong local interval " + target + "/" + width + ": " + intervals);
                for (int offset : new int[] { -1, 0, 1, 5, x86 ? 7 : 8, x86 ? 10 : 12, bytes.length }) {
                    local.setFirstUseOffset(offset);
                    require(GhidraVariableStorage.localPrefix(program, function, local, mapping, rejected,
                        TaskMonitor.DUMMY).isEmpty(), "unproved first-use accepted " + offset);
                }
                local.setFirstUseOffset(4);
                local.setName("imported", SourceType.IMPORTED);
                require(GhidraVariableStorage.localPrefix(program, function, local, mapping, rejected,
                    TaskMonitor.DUMMY).isEmpty(), "uncurated local accepted");
                local.setName("held", SourceType.USER_DEFINED);
                var detached = new LocalVariableImpl("held", 4, type, register, program, SourceType.USER_DEFINED);
                require(GhidraVariableStorage.localPrefix(program, function, detached, mapping, rejected,
                    TaskMonitor.DUMMY).isEmpty(), "detached local accepted");
                require(GhidraVariableStorage.localPrefix(program, function, local,
                    new TargetRegisterMap(target, "unmapped", java.util.Map.of("unrelated", 0)), rejected,
                    TaskMonitor.DUMMY).isEmpty(), "unmapped local accepted");
                var read = program.getListing().getInstructionAt(entry.add(4));
                read.setFlowOverride(FlowOverride.CALL);
                require(GhidraVariableStorage.localPrefix(program, function, local, mapping, rejected,
                    TaskMonitor.DUMMY).isEmpty(), "overridden flow accepted");
                read.setFlowOverride(FlowOverride.NONE);
                var reference = program.getReferenceManager().addMemoryReference(entry.add(0x100), entry.add(5),
                    RefType.UNCONDITIONAL_JUMP, SourceType.USER_DEFINED, 0);
                require(GhidraVariableStorage.localPrefix(program, function, local, mapping, rejected,
                    TaskMonitor.DUMMY).isEmpty(), "offcut second entry accepted");
                program.getReferenceManager().delete(reference);
                LocalVariable overlap = (LocalVariable) function.addLocalVariable(new LocalVariableImpl(
                    "other", x86 ? 7 : 8, type, register, program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
                require(GhidraVariableStorage.localPrefix(program, function, local, mapping, rejected,
                    TaskMonitor.DUMMY).isEmpty(), "competing local accepted");
                function.removeVariable(overlap);
                var cancelled = new TaskMonitorAdapter(true);
                cancelled.cancel();
                try {
                    GhidraVariableStorage.localPrefix(program, function, local, mapping, rejected, cancelled);
                    throw new AssertionError("cancellation ignored");
                }
                catch (CancelledException expected) { checks++; }
                require(!GhidraVariableStorage.localPrefix(program, function, local, mapping, rejected,
                    TaskMonitor.DUMMY).isEmpty(), "restored positive failed");
                // Real instruction counterexamples: no completed definition,
                // partial x86 definition, and call/opaque effects after the range.
                for (String replacement : x86 ? List.of("90909090", "41b20790") : List.of("1f2003d5")) {
                    byte[] changed = bytes.clone();
                    System.arraycopy(HexFormat.of().parseHex(replacement), 0, changed, 0, 4);
                    decode(program, entry, body, changed);
                    require(GhidraVariableStorage.localPrefix(program, function, local, mapping, rejected,
                        TaskMonitor.DUMMY).isEmpty(), "unproved initial definition accepted " + replacement);
                }
                for (String replacement : x86 ? List.of("0f05909090", "e800000000") :
                        List.of("010000d4", "01000094")) {
                    byte[] changed = bytes.clone();
                    byte[] tailBytes = HexFormat.of().parseHex(replacement);
                    System.arraycopy(tailBytes, 0, changed, x86 ? 10 : 12, tailBytes.length);
                    decode(program, entry, body, changed);
                    require(GhidraVariableStorage.localPrefix(program, function, local, mapping, rejected,
                        TaskMonitor.DUMMY).isEmpty(), "opaque/call tail accepted " + replacement);
                }
                decode(program, entry, body, bytes);
                require(!GhidraVariableStorage.localPrefix(program, function, local, mapping, rejected,
                    TaskMonitor.DUMMY).isEmpty(), "restored decoded positive failed");
                // Missing decoding after the candidate range must invalidate the proof too.
                var tail = entry.add(x86 ? 10 : 12);
                program.getListing().clearCodeUnits(tail, tail, false);
                require(GhidraVariableStorage.localPrefix(program, function, local, mapping, rejected,
                    TaskMonitor.DUMMY).isEmpty(), "undecoded tail accepted");
            }
            finally { program.endTransaction(transaction, true); }
        }
        finally { program.release(owner); }
    }

    private static void decode(ProgramDB program, ghidra.program.model.address.Address entry,
            AddressSet body, byte[] bytes) throws Exception {
        program.getListing().clearCodeUnits(body.getMinAddress(), body.getMaxAddress(), false);
        program.getMemory().setBytes(entry, bytes);
        require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY), "counterexample decode");
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
