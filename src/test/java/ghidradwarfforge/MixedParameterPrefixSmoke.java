package ghidradwarfforge;

import java.io.File;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.DynamicVariableStorage;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.CompositeStorage;
import ghidradwarfforge.locations.VariableStorageModel.RegisterRelativeStorage;
import ghidradwarfforge.locations.VariableStorageModel.RegisterStorage;
import ghidradwarfforge.locations.VariableStorageModel.Storage;

/** Actual computed ARM register/stack joins, decoded writes and SP changes. */
public final class MixedParameterPrefixSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (boolean bigEndian : new boolean[] { false, true }) {
            check(bigEndian, "08d04de204308de50030a0e308d08de21eff2fe1", 8, true);
            check(bigEndian, "00f020e31eff2fe1", 8, false);
            check(bigEndian, "0030a0e31eff2fe1", 4, false);
            check(bigEndian, "000000ef0030a0e31eff2fe1", -1, false);
            check(bigEndian, "0030a0e3000000ef1eff2fe1", -1, false);
            check(bigEndian, "000000eb0030a0e31eff2fe1", -1, false);
            // NOP; STR/LDR r0,[pc,#0x100]; BX lr. A fixed-address store still
            // ends the conservative mixed prefix; a read into r0 does not
            // modify either the r3 piece or its incoming stack companion.
            check(bigEndian, "00f020e300018fe51eff2fe1", 8, false);
            check(bigEndian, "00f020e300019fe51eff2fe1", 12, false);
        }
        System.out.println("mixed-parameter-prefix-smoke=PASS checks=" + checks);
    }

    private static void check(boolean bigEndian, String encoded, int boundary, boolean adjustsStack) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(bigEndian ? "ARM:BE:32:v8" : "ARM:LE:32:v8"));
        Object owner = new Object();
        var program = new ProgramDB("mixed-prefix", language, language.getDefaultCompilerSpec(), owner);
        try {
            int transaction = program.startTransaction("decoded mixed-storage fixture");
            try {
                byte[] bytes = HexFormat.of().parseHex(encoded);
                if (bigEndian) {
                    for (int index = 0; index < bytes.length; index += 4) {
                        byte first = bytes[index], second = bytes[index + 1];
                        bytes[index] = bytes[index + 3];
                        bytes[index + 1] = bytes[index + 2];
                        bytes[index + 2] = second;
                        bytes[index + 3] = first;
                    }
                }
                var start = language.getDefaultSpace().getAddress(0x1000);
                var body = new AddressSet(start, start.add(bytes.length - 1));
                var memory = program.getMemory().createInitializedBlock("code", start, bytes.length,
                    (byte) 0, TaskMonitor.DUMMY, false);
                memory.setExecute(true);
                program.getMemory().setBytes(start, bytes);
                program.getProgramContext().setValue(program.getRegister("TMode"), start,
                    body.getMaxAddress(), BigInteger.ZERO);
                require(new DisassembleCommand(start, body, true).applyTo(program, TaskMonitor.DUMMY), "decode failed");
                if (encoded.contains("00018fe5") || encoded.contains("00019fe5")) {
                    var access = program.getListing().getInstructionAt(start.add(4));
                    boolean writes = encoded.contains("00018fe5");
                    require(access.getMnemonicString().equals(writes ? "str" : "ldr"), "unexpected literal access");
                    require(Arrays.stream(access.getPcode()).anyMatch(op -> op.getOpcode() ==
                        (writes ? ghidra.program.model.pcode.PcodeOp.STORE : ghidra.program.model.pcode.PcodeOp.LOAD)),
                        "literal access lost its raw memory effect");
                    var operation = Arrays.stream(access.getPcode()).filter(op -> op.getOpcode() ==
                        (writes ? ghidra.program.model.pcode.PcodeOp.STORE : ghidra.program.model.pcode.PcodeOp.LOAD))
                        .findFirst().orElseThrow();
                    require(operation.getInput(1).isConstant() && operation.getInput(1).getOffset() == 0x110c,
                        "raw literal address is not the independently calculated PC+8+0x100");
                    require(Arrays.stream(access.getResultObjects()).anyMatch(start.add(0x10c)::equals) == writes,
                        "listing does not distinguish literal memory write from register-only load result");
                }
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
                require(parameter.getVariableStorage().toString().equals(bigEndian ? "r3:4,Stack[0x0]:4" : "Stack[0x0]:4,r3:4"),
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
                        "register half not first in object memory order");
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
                ownershipControls(program, function, parameter, map, rejected);
                for (int checkpoint : new int[] { 1, 4 }) {
                    var marker = new CancelledException("mixed proof cancellation " + checkpoint);
                    var cancelled = new TaskMonitorAdapter(true) {
                        private int visited;

                        @Override
                        public void checkCancelled() throws CancelledException {
                            if (++visited == checkpoint) throw marker;
                        }
                    };
                    try {
                        GhidraVariableStorage.parameterPrefix(program, function, parameter, map, rejected, cancelled);
                        throw new AssertionError("mixed proof ignored cancellation");
                    }
                    catch (CancelledException expectedCancellation) {
                        require(expectedCancellation == marker, "mixed proof changed cancellation identity");
                    }
                }
                byte[] unchanged = new byte[bytes.length];
                program.getMemory().getBytes(start, unchanged);
                require(Arrays.equals(bytes, unchanged) && function.getParameter(3) == parameter &&
                    parameter.getSource() == SourceType.USER_DEFINED && function.getBody().equals(body),
                    "refusals or cancellation changed original bytes or curated parameter");
                require(intervals.equals(GhidraVariableStorage.parameterPrefix(program, function, parameter,
                    map, rejected, TaskMonitor.DUMMY)), "refusal or cancellation poisoned later mixed proof");
                program.getListing().clearCodeUnits(start, start.add(3), false);
                require(GhidraVariableStorage.parameterPrefix(program, function, parameter, map, rejected,
                    TaskMonitor.DUMMY).isEmpty(), "listing gap accepted");
            }
            finally {
                program.endTransaction(transaction, false);
            }
            require(program.getFunctionManager().getFunctionCount() == 0 && program.getMemory().getBlocks().length == 0,
                "fixture rollback retained functions or bytes");
        }
        finally {
            program.flushEvents();
            program.release(owner);
        }
    }

    private static void ownershipControls(ProgramDB program, Function function, Parameter parameter,
            TargetRegisterMap map, Storage rejected) throws Exception {
        Object owner = new Object();
        var foreign = new ProgramDB("foreign-mixed", program.getLanguage(),
            program.getLanguage().getDefaultCompilerSpec(), owner);
        try {
            var storage = parameter.getVariableStorage();
            var entry = function.getEntryPoint();
            var other = program.getFunctionManager().createFunction("other", entry.add(0x100),
                new AddressSet(entry.add(0x100), entry.add(0x100)), SourceType.USER_DEFINED);
            require(GhidraVariableStorage.parameterPrefix(foreign, function, parameter, storage, map, rejected,
                TaskMonitor.DUMMY).isEmpty(), "foreign program acquired mixed proof");
            require(GhidraVariableStorage.parameterPrefix(program, other, parameter, storage, map, rejected,
                TaskMonitor.DUMMY).isEmpty(), "foreign function acquired mixed proof");
            var detached = new ParameterImpl("detached", parameter.getFormalDataType(), storage, program);
            require(GhidraVariableStorage.parameterPrefix(program, function, detached, storage, map, rejected,
                TaskMonitor.DUMMY).isEmpty(), "unsaved parameter acquired mixed proof");
            require(GhidraVariableStorage.parameterPrefix(program, function, function.getReturn(), storage, map, rejected,
                TaskMonitor.DUMMY).isEmpty(), "return acquired incoming mixed proof");
            var stack = new Varnode(program.getAddressFactory().getStackSpace().getAddress(0), 8);
            var register = new Varnode(program.getRegister("r3").getAddress(), 4);
            var oversized = new VariableStorage(program, program.getLanguage().isBigEndian()
                ? new Varnode[] { register, stack } : new Varnode[] { stack, register });
            require(oversized.isValid() && oversized.size() == 12 && parameter.getLength() == 8,
                "size rejection must reach a valid carrier for an attached eight-byte formal");
            VariableStorage[] invalid = { new VariableStorage(foreign, storage.getVarnodes()), oversized,
                new DynamicVariableStorage(program, true, storage.getVarnodes()) };
            String[] reasons = { "foreign storage", "formal/carrier size mismatch", "forced indirect mixed carrier" };
            for (int index = 0; index < invalid.length; index++) {
                require(GhidraVariableStorage.parameterPrefix(program, function, parameter, invalid[index], map,
                    rejected, TaskMonitor.DUMMY).isEmpty(), reasons[index] + " acquired mixed proof");
            }
            for (var numbers : List.of(Map.of("sp", 13), Map.of("r3", 3))) {
                var missing = new TargetRegisterMap("incomplete-arm", "explicit absent carrier mapping", numbers);
                require(GhidraVariableStorage.parameterPrefix(program, function, parameter, storage, missing, rejected,
                    TaskMonitor.DUMMY).isEmpty(), "unmapped register or stack base acquired mixed proof");
            }
            var body = new AddressSet(function.getBody());
            try {
                var discontiguous = new AddressSet(body);
                discontiguous.add(entry.add(0x40), entry.add(0x43));
                function.setBody(discontiguous);
                require(GhidraVariableStorage.parameterPrefix(program, function, parameter, storage, map, rejected,
                    TaskMonitor.DUMMY).isEmpty(), "discontiguous body acquired a linear mixed prefix");
                function.setBody(new AddressSet(entry.subtract(4), body.getMaxAddress()));
                require(GhidraVariableStorage.parameterPrefix(program, function, parameter, storage, map, rejected,
                    TaskMonitor.DUMMY).isEmpty(), "bytes before entry acquired an incoming mixed prefix");
            }
            finally {
                function.setBody(body);
            }
        }
        finally {
            foreign.flushEvents();
            foreign.release(owner);
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
        checks++;
    }
}
