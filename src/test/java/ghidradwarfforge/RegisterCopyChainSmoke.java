package ghidradwarfforge;

import java.io.File;
import java.lang.reflect.Proxy;
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
import ghidra.program.model.lang.DynamicVariableStorage;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.RegisterStorage;
import ghidradwarfforge.locations.VariableStorageModel.Storage;

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
                if (handoffs == 3 && !loseLast) {
                    ownership(program, function, parameter, mapping, rejected, intervals);
                }
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

    private static void ownership(ProgramDB program, Function original, Parameter saved,
            TargetRegisterMap registers, Storage rejected,
            List<GhidraVariableStorage.StorageInterval> expected) throws Exception {
        long modification = program.getModificationNumber();
        var originalStorage = saved.getVariableStorage();
        Object owner = new Object();
        var foreign = new ProgramDB("foreign-chain", program.getLanguage(),
            program.getLanguage().getCompilerSpecByID(program.getCompilerSpec().getCompilerSpecID()), owner);
        try {
            for (String mode : List.of("coherent", "foreign-function", "foreign-storage", "other-function",
                    "negative-ordinal", "different-saved-row", "later-first-use", "indirect-storage")) {
                Parameter[] subject = new Parameter[1];
                Function[] binding = new Function[1];
                VariableStorage storage = switch (mode) {
                    case "foreign-storage" -> new VariableStorage(foreign, originalStorage.getVarnodes());
                    case "indirect-storage" -> new DynamicVariableStorage(program, true, originalStorage.getVarnodes());
                    default -> originalStorage;
                };
                binding[0] = (Function) Proxy.newProxyInstance(Function.class.getClassLoader(),
                    new Class<?>[] {Function.class}, (proxy, method, arguments) -> switch (method.getName()) {
                        case "getProgram" -> mode.equals("foreign-function") ? foreign : program;
                        case "getParameter" -> mode.equals("different-saved-row") ? saved : subject[0];
                        default -> method.invoke(original, arguments);
                    });
                subject[0] = (Parameter) Proxy.newProxyInstance(Parameter.class.getClassLoader(),
                    new Class<?>[] {Parameter.class}, (proxy, method, arguments) -> switch (method.getName()) {
                        case "getFunction" -> mode.equals("other-function") ? original : binding[0];
                        case "getOrdinal" -> mode.equals("negative-ordinal") ? -1 : saved.getOrdinal();
                        case "getFirstUseOffset" -> mode.equals("later-first-use") ? 1 : 0;
                        case "getVariableStorage" -> storage;
                        default -> method.invoke(saved, arguments);
                    });
                var actual = GhidraVariableStorage.parameterPrefix(program, binding[0], subject[0], storage,
                    registers, rejected, TaskMonitor.DUMMY);
                if (mode.equals("coherent")) {
                    require(actual.equals(expected), "consistent views retain the entire proven copy chain");
                    require(!StackValueFlow.prove(program, binding[0], subject[0], storage,
                        registers, TaskMonitor.DUMMY).isEmpty(), "consistent identity must admit value-flow proof");
                }
                else {
                    // The first completed copy has its own instruction proof. Subsequent
                    // composition must stop when saved incoming-value identity disagrees.
                    require(actual.size() == 3 && actual.get(0).equals(expected.get(0)) &&
                        actual.get(1).equals(expected.get(1)) && !actual.get(2).storage().available() &&
                        actual.get(2).start() == expected.get(1).end() &&
                        actual.get(2).end() == expected.getLast().end(),
                        mode + " must retain only the independently proven first backup: " + actual);
                    require(StackValueFlow.prove(program, binding[0], subject[0], storage,
                        registers, TaskMonitor.DUMMY).isEmpty(), mode + " must not seed a later value-flow proof");
                }
            }
            require(program.getModificationNumber() == modification && original.getParameter(0) == saved &&
                originalStorage.equals(saved.getVariableStorage()), "identity controls changed saved parameter");
            require(GhidraVariableStorage.parameterPrefix(program, original, saved, registers, rejected,
                TaskMonitor.DUMMY).equals(expected), "identity refusal poisoned a later valid proof");
        }
        finally { foreign.release(owner); }
    }

    private static void require(boolean condition, String detail) {
        checks++;
        if (!condition) throw new AssertionError(detail);
    }
}
