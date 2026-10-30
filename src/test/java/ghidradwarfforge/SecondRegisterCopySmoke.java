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
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.RegisterStorage;

/** Real decoder boundaries for a second completed backup, including stale copies. */
public final class SecondRegisterCopySmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (String target : List.of("x86_64", "aarch64")) {
            for (int bytes : new int[] { 4, 8 }) {
                boolean x86 = target.equals("x86_64");
                String copy = x86 ? (bytes == 4 ? "4589d3" : "4d89d3") :
                    (bytes == 4 ? "ea03092a" : "ea0309aa");
                String initial = x86 ? (bytes == 4 ? "4189fa" : "4989fa") :
                    (bytes == 4 ? "e903002a" : "e90300aa");
                String nop = x86 ? "90" : "1f2003d5";
                String originalKill = x86 ? "4831ff" : "e0031faa";
                String firstKill = x86 ? "4d31d2" : "e9031faa";
                String secondKill = x86 ? "4d31db" : "ea031faa";
                String ret = x86 ? "c3" : "c0035fd6";
                String prefix = initial + nop + originalKill + nop;
                String suffix = nop + firstKill + nop + secondKill + nop + ret;
                check(target, bytes, prefix + copy + suffix, x86 ? 15 : 28, x86 ? 19 : 36, true);
                // A partial clobber ends the whole value at the completed instruction.
                if (x86) check(target, bytes, prefix + copy + nop + firstKill + nop +
                    "41b301" + nop + ret, 15, 19, true);
                // No copy, a changed arithmetic value, or a stale pre-handoff copy.
                check(target, bytes, prefix + (x86 ? "909090" : nop) + suffix, 0, 0, false);
                check(target, bytes, prefix + (x86 ? "4d01d3" : "4a010991") + suffix, 0, 0, false);
                check(target, bytes, initial + copy + nop + originalKill + nop +
                    firstKill + nop + secondKill + nop + ret, 0, 0, false);
                // A second copy killed before handoff is not a surviving fact.
                check(target, bytes, prefix + copy + nop + secondKill + nop + firstKill + nop + ret, 0, 0, false);
                // A self-copy of the first backup creates different physical and
                // semantic write boundaries. Do not join mismatched proofs.
                check(target, bytes, prefix + copy + nop + (x86 ? (bytes == 4 ? "4589d2" : "4d89d2") : (bytes == 4 ? "e903092a" : "e90309aa")) +
                    nop + firstKill + nop + secondKill + nop + ret, 0, 0, false);
                // Copying the first register only after its kill cannot resurrect it.
                check(target, bytes, prefix + firstKill + nop + copy + nop + secondKill + nop + ret, 0, 0, false);
            }
        }
        System.out.println("second-register-copy-smoke=PASS checks=" + checks);
    }

    private static void check(String target, int bytes, String hex, int secondStart,
            int secondEnd, boolean available) throws Exception {
        boolean x86 = target.equals("x86_64");
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(
            x86 ? "x86:LE:64:default" : "AARCH64:LE:64:v8A"));
        Object owner = new Object();
        var program = new ProgramDB("second-copy", language, language.getDefaultCompilerSpec(), owner);
        try {
            int tx = program.startTransaction("second-copy decoder fixture");
            try {
                byte[] code = HexFormat.of().parseHex(hex);
                var entry = language.getDefaultSpace().getAddress(0x1000);
                var body = new AddressSet(entry, entry.add(code.length - 1));
                var block = program.getMemory().createInitializedBlock("code", entry, code.length,
                    (byte) 0, TaskMonitor.DUMMY, false);
                block.setExecute(true);
                program.getMemory().setBytes(entry, code);
                require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY), "decode");
                var function = program.getFunctionManager().createFunction("chain", entry, body, SourceType.USER_DEFINED);
                var type = bytes == 4 ? IntegerDataType.dataType : LongLongDataType.dataType;
                var register = program.getRegister(x86 ? (bytes == 4 ? "EDI" : "RDI") : (bytes == 4 ? "w0" : "x0"));
                function.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE, true,
                    SourceType.USER_DEFINED, new ParameterImpl("value", type, register, program, SourceType.USER_DEFINED));
                var parameter = function.getParameter(0);
                var mapping = TargetRegisterMap.forTarget(target);
                var rejected = GhidraVariableStorage.stableParameter(program, function, parameter, mapping, TaskMonitor.DUMMY);
                var intervals = GhidraVariableStorage.parameterPrefix(program, function, parameter, mapping, rejected, TaskMonitor.DUMMY);
                int secondRegister = x86 ? 11 : 10;
                var second = intervals.stream().filter(i -> i.storage() instanceof RegisterStorage r &&
                    r.register().dwarfNumber() == secondRegister).toList();
                require(available ? second.size() == 1 && second.get(0).start() == 0x1000 + secondStart &&
                    second.get(0).end() == 0x1000 + secondEnd : second.isEmpty(), target + "/" + bytes + " " + hex + " " + intervals);
                require(!intervals.isEmpty() && !intervals.getLast().storage().available() &&
                    intervals.getLast().end() == 0x1000 + code.length, "explicit unavailable tail");
                for (int i = 1; i < intervals.size(); i++) {
                    require(intervals.get(i - 1).end() == intervals.get(i).start(), "contiguous interval coverage");
                }
                var cancelled = new TaskMonitorAdapter(true);
                cancelled.cancel();
                try {
                    GhidraVariableStorage.parameterPrefix(program, function, parameter, mapping, rejected, cancelled);
                    throw new AssertionError("cancellation ignored");
                }
                catch (CancelledException expected) { checks++; }
            }
            finally { program.endTransaction(tx, true); }
        }
        finally { program.release(owner); }
    }

    private static void require(boolean condition, String detail) {
        checks++;
        if (!condition) throw new AssertionError(detail);
    }
}
