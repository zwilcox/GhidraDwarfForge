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
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.LocalVariable;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.locations.TargetRegisterMap;

/** Real decoded diamonds, loops and split bodies; no fabricated instruction graph. */
public final class LocalDefinitionFlowSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (boolean x86 : new boolean[] { true, false }) {
            for (int bytes : new int[] { 4, 8 }) {
                for (String shape : List.of("diamond", "loop", "split", "bypass")) {
                    check(x86, bytes, shape, false);
                    if (!shape.equals("bypass")) check(x86, bytes, shape, true);
                }
            }
        }
        System.out.println("local-definition-flow-smoke=PASS checks=" + checks);
    }

    private static void check(boolean x86, int bytes, String shape, boolean kill) throws Exception {
        String target = x86 ? "x86_64" : "aarch64";
        String nop = x86 ? "90" : "1f2003d5";
        String define = x86 ? (bytes == 4 ? "41ba07000000" : "49c7c207000000") :
            (bytes == 4 ? "e9008052" : "e90080d2");
        String clobber = x86 ? "4531d2" : "e9031f2a";
        String result = x86 ? (bytes == 4 ? "4489d0" : "4c89d0") :
            (bytes == 4 ? "e003092a" : "e00309aa");
        String ret = x86 ? "c3" : "c0035fd6";
        String before = nop;
        if (shape.equals("bypass")) {
            before += x86 ? "85ff74" + HexFormat.of().toHexDigits((byte) ((define.length() + nop.length()) / 2)) :
                "1f00007160000054";
        }
        int firstUse = before.length() / 2;
        String prefix = before + define;
        int ready = prefix.length() / 2;
        String middle = switch (shape) {
            case "diamond" -> x86 ? "85ff7404" + (kill ? clobber : "909090") + nop :
                "1f00007160000054" + (kill ? clobber : nop) + nop;
            case "loop" -> nop + (x86 ? (kill ? clobber + "ffcf75f9" : "ffcf75fc") :
                (kill ? clobber + "00040071c1ffff54" : "00040071e1ffff54"));
            case "split" -> x86 ? "eb03cccccc" : "02000014000020d4";
            case "bypass" -> nop;
            default -> throw new AssertionError(shape);
        };
        byte[] code = HexFormat.of().parseHex(prefix + middle + result + ret);
        int join = ready + middle.length() / 2;
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(
            x86 ? "x86:LE:64:default" : "AARCH64:LE:64:v8A"));
        Object owner = new Object();
        var program = new ProgramDB("local-definition-flow", language, language.getDefaultCompilerSpec(), owner);
        try {
            int tx = program.startTransaction("decoded control flow");
            try {
                var entry = language.getDefaultSpace().getAddress(0x1000);
                var body = new AddressSet(entry, entry.add(code.length - 1));
                var block = program.getMemory().createInitializedBlock("code", entry, code.length,
                    (byte) 0, TaskMonitor.DUMMY, false);
                block.setExecute(true);
                program.getMemory().setBytes(entry, code);
                if (shape.equals("split") && !kill) {
                    body.delete(entry.add(ready + (x86 ? 2 : 4)), entry.add(join - 1));
                }
                require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY), "decode");
                var function = program.getFunctionManager().createFunction("local_flow", entry, body, SourceType.USER_DEFINED);
                var type = bytes == 4 ? IntegerDataType.dataType : LongLongDataType.dataType;
                var register = program.getRegister(x86 ? (bytes == 4 ? "R10D" : "R10") :
                    (bytes == 4 ? "w9" : "x9"));
                var local = (LocalVariable) function.addLocalVariable(new LocalVariableImpl("held", firstUse,
                    type, register, program, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
                var map = TargetRegisterMap.forTarget(target);
                var rejected = GhidraVariableStorage.stableLocal(program, function, local, map, TaskMonitor.DUMMY);
                var intervals = RegisterDefinitionFlow.prove(program, function, local, map, rejected, TaskMonitor.DUMMY);
                String context = target + "/" + bytes + "/" + shape + "/kill=" + kill + " " + intervals;
                if (shape.equals("split") && kill) {
                    require(intervals.isEmpty(), "undecoded included gap accepted " + context);
                    return;
                }
                require(!intervals.isEmpty(), "missing proof " + context);
                require(!available(intervals, 0x1000), "stale entry value " + context);
                require(!available(intervals, 0x1000 + firstUse), "unfinished definition " + context);
                require(available(intervals, 0x1000 + join) == (!kill && !shape.equals("bypass")),
                    "join agreement " + context);
                if (shape.equals("bypass")) {
                    require(available(intervals, 0x1000 + ready), "defined path before join " + context);
                }
                if (shape.equals("diamond")) {
                    require(available(intervals, 0x1000 + ready), "prefix before branch " + context);
                    int killAddress = ready + (x86 ? 4 : 8);
                    require(available(intervals, 0x1000 + killAddress), "pre-execution write state " + context);
                    require(available(intervals, 0x1000 + killAddress + (x86 ? 3 : 4)) == !kill,
                        "completed write boundary " + context);
                }
                if (shape.equals("loop")) {
                    require(available(intervals, 0x1000 + ready), "established value before loop " + context);
                    require(available(intervals, 0x1000 + ready + nop.length() / 2) == !kill,
                        "loop backedge agreement " + context);
                }
                for (var interval : intervals) {
                    require(body.contains(entry.getAddressSpace().getAddress(interval.start()),
                        entry.getAddressSpace().getAddress(interval.end() - 1)), "interval crossed body hole " + context);
                }
                var cancelled = new TaskMonitorAdapter(true);
                cancelled.cancel();
                try {
                    RegisterDefinitionFlow.prove(program, function, local, map, rejected, cancelled);
                    throw new AssertionError("cancellation ignored");
                }
                catch (CancelledException expected) {
                    checks++;
                }
                local.setFirstUseOffset(firstUse + 1);
                require(RegisterDefinitionFlow.prove(program, function, local, map, rejected,
                    TaskMonitor.DUMMY).isEmpty(), "offcut definition accepted " + context);
                local.setFirstUseOffset(firstUse);
                var references = program.getReferenceManager();
                var ordinaryEntry = references.addMemoryReference(entry.subtract(16), entry,
                    RefType.UNCONDITIONAL_JUMP, SourceType.USER_DEFINED, 0);
                require(RegisterDefinitionFlow.prove(program, function, local, map, rejected,
                    TaskMonitor.DUMMY).equals(intervals), "ordinary entry rejected " + context);
                references.delete(ordinaryEntry);
                var secondaryEntry = references.addMemoryReference(entry.subtract(16), entry.add(join),
                    RefType.UNCONDITIONAL_JUMP, SourceType.USER_DEFINED, 0);
                require(RegisterDefinitionFlow.prove(program, function, local, map, rejected,
                    TaskMonitor.DUMMY).isEmpty(), "unproved alternate entry accepted " + context);
                references.delete(secondaryEntry);
                var instruction = program.getListing().getInstructionAt(entry.add(firstUse));
                instruction.setFlowOverride(FlowOverride.CALL);
                require(RegisterDefinitionFlow.prove(program, function, local, map, rejected,
                    TaskMonitor.DUMMY).isEmpty(), "flow override accepted " + context);
                instruction.setFlowOverride(FlowOverride.NONE);
                require(RegisterDefinitionFlow.prove(program, function, local, map, rejected,
                    TaskMonitor.DUMMY).equals(intervals), "controls did not restore proof " + context);
            }
            finally {
                program.endTransaction(tx, true);
            }
        }
        finally {
            program.release(owner);
        }
    }

    private static boolean available(List<GhidraVariableStorage.StorageInterval> intervals, long address) {
        return intervals.stream().anyMatch(interval -> interval.start() <= address && address < interval.end() &&
            interval.storage().available());
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
