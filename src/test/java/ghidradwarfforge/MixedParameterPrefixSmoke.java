package ghidradwarfforge;

import java.io.File;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.util.HexFormat;
import java.util.List;

import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.CompositeStorage;
import ghidradwarfforge.locations.VariableStorageModel.RegisterRelativeStorage;
import ghidradwarfforge.locations.VariableStorageModel.RegisterStorage;

/** Actual computed ARM register/stack joins, decoded writes and SP changes. */
public final class MixedParameterPrefixSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        check("08d04de204308de50030a0e308d08de21eff2fe1", 8, true);
        check("00f020e31eff2fe1", 8, false);
        check("0030a0e31eff2fe1", 4, false);
        check("000000ef0030a0e31eff2fe1", -1, false);
        check("0030a0e3000000ef1eff2fe1", -1, false);
        check("000000eb0030a0e31eff2fe1", -1, false);
        System.out.println("mixed-parameter-prefix-smoke=PASS checks=" + checks);
    }

    private static void check(String encoded, int boundary, boolean adjustsStack) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("ARM:LE:32:v8"));
        Object owner = new Object();
        var program = new ProgramDB("mixed-prefix", language, language.getDefaultCompilerSpec(), owner);
        try {
            int transaction = program.startTransaction("decoded mixed-storage fixture");
            try {
                byte[] bytes = HexFormat.of().parseHex(encoded);
                var start = language.getDefaultSpace().getAddress(0x1000);
                var body = new AddressSet(start, start.add(bytes.length - 1));
                var memory = program.getMemory().createInitializedBlock("code", start, bytes.length,
                    (byte) 0, TaskMonitor.DUMMY, false);
                memory.setExecute(true);
                program.getMemory().setBytes(start, bytes);
                program.getProgramContext().setValue(program.getRegister("TMode"), start,
                    body.getMaxAddress(), BigInteger.ZERO);
                require(new DisassembleCommand(start, body, true).applyTo(program, TaskMonitor.DUMMY), "decode failed");
                Function function = program.getFunctionManager().createFunction("mixed", start, body, SourceType.USER_DEFINED);
                var integer = new IntegerDataType(program.getDataTypeManager());
                var pair = new StructureDataType("MixedPair", 0, program.getDataTypeManager());
                pair.add(integer, "low", null);
                pair.add(integer, "high", null);
                function.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
                function.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true,
                    SourceType.USER_DEFINED, new ParameterImpl("a", integer, program),
                    new ParameterImpl("b", integer, program), new ParameterImpl("c", integer, program),
                    new ParameterImpl("pair", pair, program));
                Parameter parameter = function.getParameter(3);
                require(parameter.getVariableStorage().toString().equals("Stack[0x0]:4,r3:4"),
                    "actual computed join changed: " + parameter.getVariableStorage());
                var map = TargetRegisterMap.forTarget("arm");
                var rejected = GhidraVariableStorage.stableParameter(program, function, parameter, map, TaskMonitor.DUMMY);
                require(!rejected.available(), "mixed storage unexpectedly stable");
                var intervals = GhidraVariableStorage.parameterPrefix(program, function, parameter, map, rejected, TaskMonitor.DUMMY);
                if (boundary < 0) {
                    require(intervals.isEmpty(), "opaque/call instruction acquired mixed storage: " + intervals);
                    return;
                }
                require(!intervals.isEmpty(), "missing mixed prefix");
                long expected = 0x1000;
                for (var interval : intervals) {
                    require(interval.start() == expected, "location gap");
                    expected = interval.end();
                    if (interval.start() >= 0x1000 + boundary) {
                        require(!interval.storage().available(), "write retained mixed value");
                        continue;
                    }
                    require(interval.storage() instanceof CompositeStorage, "mixed value not composite");
                    var pieces = ((CompositeStorage) interval.storage()).pieces();
                    require(pieces.size() == 2 && pieces.stream().allMatch(piece -> piece.bitSize() == 32), "wrong sizes");
                    require(pieces.get(0).storage() instanceof RegisterStorage r && r.register().dwarfNumber() == 3,
                        "register half not first in little-endian memory order");
                    long offset = adjustsStack && interval.start() > 0x1000 ? 8 : 0;
                    require(pieces.get(1).storage() instanceof RegisterRelativeStorage r &&
                        r.register().dwarfNumber() == 13 && r.byteOffset() == offset, "SP coordinate was not adjusted");
                    require(interval.end() <= 0x1000 + boundary, "location crosses possible write");
                }
                require(expected == 0x1000 + bytes.length, "missing explicit tail");
                function.setCustomVariableStorage(true);
                parameter = function.getParameter(3);
                require(intervals.equals(GhidraVariableStorage.parameterPrefix(program, function, parameter,
                    map, rejected, TaskMonitor.DUMMY)), "analyst custom storage changed the proven mixed prefix");
                Parameter attached = parameter;
                Parameter wrongSize = (Parameter) Proxy.newProxyInstance(Parameter.class.getClassLoader(),
                    new Class<?>[] { Parameter.class }, (proxy, method, arguments) ->
                        method.getName().equals("getLength") ? 7 : method.invoke(attached, arguments));
                require(GhidraVariableStorage.parameterPrefix(program, function, wrongSize, map, rejected,
                    TaskMonitor.DUMMY).isEmpty(), "formal/storage mismatch accepted");
                var cancelled = new TaskMonitorAdapter(true);
                cancelled.cancel();
                try {
                    GhidraVariableStorage.parameterPrefix(program, function, parameter, map, rejected, cancelled);
                    throw new AssertionError("mixed proof ignored cancellation");
                }
                catch (CancelledException expectedCancellation) {
                    checks++;
                }
                program.getListing().clearCodeUnits(start, start.add(3), false);
                require(GhidraVariableStorage.parameterPrefix(program, function, parameter, map, rejected,
                    TaskMonitor.DUMMY).isEmpty(), "listing gap accepted");
            }
            finally {
                program.endTransaction(transaction, false);
            }
        }
        finally {
            program.release(owner);
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
        checks++;
    }
}
