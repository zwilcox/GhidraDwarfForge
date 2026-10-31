package ghidradwarfforge;

import java.io.File;
import java.util.ArrayList;
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

/** Decoded repeated handoffs, including reuse of a previously killed register. */
public final class RegisterCopyChainSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (boolean x86 : new boolean[] { true, false }) {
            for (int bytes : new int[] { 4, 8 }) {
                for (int handoffs : new int[] { 3, 4, 12 }) {
                    check(x86, bytes, handoffs, false);
                    check(x86, bytes, handoffs, true);
                }
            }
        }
        System.out.println("register-copy-chain-smoke=PASS checks=" + checks);
    }

    private static void check(boolean x86, int bytes, int handoffs, boolean loseLast)
            throws Exception {
        String target = x86 ? "x86_64" : "aarch64";
        String nop = x86 ? "90" : "1f2003d5";
        String originalKill = x86 ? "4831ff" : "e0031faa";
        String firstKill = x86 ? "4d31d2" : "e9031faa";
        String secondKill = x86 ? "4d31db" : "ea031faa";
        String forward = x86 ? (bytes == 4 ? "4589d3" : "4d89d3") :
            (bytes == 4 ? "ea03092a" : "ea0309aa");
        String backward = x86 ? (bytes == 4 ? "4589da" : "4d89da") :
            (bytes == 4 ? "e9030a2a" : "e9030aaa");
        String initial = x86 ? (bytes == 4 ? "4189fa" : "4989fa") :
            (bytes == 4 ? "e903002a" : "e90300aa");
        StringBuilder code = new StringBuilder(initial + nop + originalKill);
        List<Integer> boundaries = new ArrayList<>();
        boundaries.add(code.length() / 2);
        for (int handoff = 2; handoff <= handoffs; handoff++) {
            code.append(nop);
            // Destroy the only surviving value before the final copy. The same
            // register spellings later in the body must not resurrect the fact.
            String kill = handoff % 2 == 0 ? firstKill : secondKill;
            if (loseLast && handoff == handoffs) {
                code.append(kill);
                boundaries.add(code.length() / 2);
                code.append(nop).append(handoff % 2 == 0 ? forward : backward);
            }
            else {
                code.append(handoff % 2 == 0 ? forward : backward).append(nop).append(kill);
                boundaries.add(code.length() / 2);
            }
        }
        code.append(nop).append(handoffs % 2 == 0 ? secondKill : firstKill);
        if (!loseLast) boundaries.add(code.length() / 2);
        code.append(nop).append(x86 ? "c3" : "c0035fd6");
        byte[] raw = HexFormat.of().parseHex(code.toString());
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(
            x86 ? "x86:LE:64:default" : "AARCH64:LE:64:v8A"));
        Object owner = new Object();
        var program = new ProgramDB("copy-chain", language, language.getDefaultCompilerSpec(), owner);
        try {
            int tx = program.startTransaction("register chain fixture");
            try {
                var entry = language.getDefaultSpace().getAddress(0x1000);
                var body = new AddressSet(entry, entry.add(raw.length - 1));
                var block = program.getMemory().createInitializedBlock("code", entry, raw.length,
                    (byte) 0, TaskMonitor.DUMMY, false);
                block.setExecute(true);
                program.getMemory().setBytes(entry, raw);
                require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY), "decode");
                var function = program.getFunctionManager().createFunction("chain", entry, body, SourceType.USER_DEFINED);
                var type = bytes == 4 ? IntegerDataType.dataType : LongLongDataType.dataType;
                var register = program.getRegister(x86 ? (bytes == 4 ? "EDI" : "RDI") :
                    (bytes == 4 ? "w0" : "x0"));
                function.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE, true,
                    SourceType.USER_DEFINED, new ParameterImpl("value", type, register, program, SourceType.USER_DEFINED));
                var parameter = function.getParameter(0);
                var mapping = TargetRegisterMap.forTarget(target);
                var rejected = GhidraVariableStorage.stableParameter(program, function, parameter, mapping, TaskMonitor.DUMMY);
                var intervals = GhidraVariableStorage.parameterPrefix(program, function, parameter, mapping, rejected, TaskMonitor.DUMMY);
                String context = target + "/" + bytes + "/" + handoffs + "/lost=" + loseLast + " " + intervals;
                require(intervals.size() == boundaries.size() + 1, "interval count " + context);
                long start = 0x1000;
                for (int index = 0; index < boundaries.size(); index++) {
                    var interval = intervals.get(index);
                    int dwarf = index == 0 ? (x86 ? 5 : 0) :
                        (x86 ? (index % 2 == 1 ? 10 : 11) : (index % 2 == 1 ? 9 : 10));
                    require(interval.start() == start && interval.end() == 0x1000 + boundaries.get(index),
                        "instruction boundary " + context);
                    require(interval.storage() instanceof RegisterStorage r && r.register().dwarfNumber() == dwarf,
                        "register identity " + context);
                    start = interval.end();
                }
                var tail = intervals.getLast();
                require(!tail.storage().available() && tail.start() == start && tail.end() == 0x1000 + raw.length,
                    "unavailable tail " + context);
                var cancelled = new TaskMonitorAdapter(true);
                cancelled.cancel();
                try {
                    GhidraVariableStorage.parameterPrefix(program, function, parameter, mapping, rejected, cancelled);
                    throw new AssertionError("cancellation ignored");
                }
                catch (CancelledException expected) {
                    checks++;
                }
            }
            finally {
                program.endTransaction(tx, true);
            }
        }
        finally {
            program.release(owner);
        }
    }

    private static void require(boolean condition, String detail) {
        checks++;
        if (!condition) throw new AssertionError(detail);
    }
}
