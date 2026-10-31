package ghidradwarfforge;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import db.DBHandle;
import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.data.OpenMode;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedLongLongDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.DynamicVariableStorage;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.GhidraVariableStorage.StorageInterval;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.dwarf.Dwarf5LocationLists;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.Confidence;
import ghidradwarfforge.locations.VariableStorageModel.CompositeStorage;
import ghidradwarfforge.locations.VariableStorageModel.Evidence;
import ghidradwarfforge.locations.VariableStorageModel.LocationRange;
import ghidradwarfforge.locations.VariableStorageModel.OmissionReason;
import ghidradwarfforge.locations.VariableStorageModel.RegisterStorage;
import ghidradwarfforge.locations.VariableStorageModel.Storage;
import ghidradwarfforge.locations.VariableStorageModel.UnavailableStorage;
import ghidradwarfforge.locations.VariableStorageModel.VariableKind;
import ghidradwarfforge.locations.VariableStorageModel.VariableLocation;

/** Actual decoded incoming joins, then controlled malformed proof inputs. */
public final class CompositeRegisterPrefixSmoke {
    private record Target(String language, String map, String code, int boundary,
            String first, String second) {
    }

    private static int checks;

    private CompositeRegisterPrefixSmoke() {
    }

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (Target target : List.of(
                new Target("x86:LE:64:default", "x86_64",
                    "4889f8906631ff904889050b2f0000488935fc2e0000c3", 7, "RDI", "RSI"),
                new Target("AARCH64:LE:64:v8A", "aarch64",
                    "e20300aa1f2003d5e0031f2a1f2003d50001009003c00091021800f9610400f9c0035fd6",
                    12, "x0", "x1"))) {
            actual(target);
        }
        bigEndianControl();
        System.out.println("composite-register-prefix-smoke=PASS checks=" + checks);
    }

    private static void actual(Target target) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(target.language()));
        var compiler = target.map().equals("x86_64")
            ? language.getCompilerSpecByID(new CompilerSpecID("gcc")) : language.getDefaultCompilerSpec();
        Object owner = new Object();
        ProgramDB program = new ProgramDB("composite-prefix", language, compiler, owner);
        var directory = Files.createTempDirectory("forge-composite-prefix-");
        var saved = directory.resolve("program.db");
        try {
            int transaction = program.startTransaction("decoded incoming composite");
            try {
                byte[] code = HexFormat.of().parseHex(target.code());
                var start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
                var body = new AddressSet(start, start.add(code.length - 1));
                var block = program.getMemory().createInitializedBlock("code", start, code.length,
                    (byte) 0, TaskMonitor.DUMMY, false);
                block.setExecute(true);
                program.getMemory().setBytes(start, code);
                require(new DisassembleCommand(start, body, true).applyTo(program, TaskMonitor.DUMMY), "decode failed");
                Function function = program.getFunctionManager().createFunction("capture_pair", start, body, SourceType.USER_DEFINED);
                var pair = new StructureDataType("Pair", 0, program.getDataTypeManager());
                pair.add(new UnsignedLongLongDataType(program.getDataTypeManager()), "first", null);
                pair.add(new UnsignedLongLongDataType(program.getDataTypeManager()), "second", null);
                require(pair.getLength() == 16, "pair layout changed");
                function.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
                function.updateFunction(null, function.getReturn(), Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                    true, SourceType.USER_DEFINED, new ParameterImpl("value", pair, program, SourceType.USER_DEFINED));
                observe(program, function, target, false);
                controlled(program, function, target);
                var nodes = function.getParameter(0).getVariableStorage().getVarnodes();
                function.setCustomVariableStorage(true);
                require(Arrays.equals(nodes, function.getParameter(0).getVariableStorage().getVarnodes()), "conversion changed join");
                observe(program, function, target, true);
            }
            finally {
                program.endTransaction(transaction, true);
            }
            program.getDBHandle().saveAs(saved.toFile(), false, TaskMonitor.DUMMY);
            byte[] before = Files.readAllBytes(saved);
            var mtime = Files.getLastModifiedTime(saved);
            Object reader = new Object();
            DBHandle handle = new DBHandle(saved.toFile());
            ProgramDB reopened = null;
            try {
                reopened = new ProgramDB(handle, OpenMode.IMMUTABLE, TaskMonitor.DUMMY, reader);
                observe(reopened, reopened.getFunctionManager().getFunctionAt(
                    reopened.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000)), target, true);
            }
            finally {
                if (reopened == null) {
                    handle.close();
                }
                else {
                    reopened.release(reader);
                }
            }
            require(Arrays.equals(before, Files.readAllBytes(saved)) && mtime.equals(Files.getLastModifiedTime(saved)),
                "immutable reopening modified database");
            System.out.println("composite-register-prefix-target=PASS " + target.language());
        }
        finally {
            program.release(owner);
            Files.deleteIfExists(saved);
            Files.deleteIfExists(directory);
        }
    }

    private static void observe(Program program, Function function, Target target, boolean custom) throws Exception {
        Parameter parameter = function.getParameter(0);
        var map = TargetRegisterMap.forTarget(target.map());
        var nodes = parameter.getVariableStorage().getVarnodes();
        require(function.hasCustomVariableStorage() == custom && parameter.hasAssignedStorage() == custom &&
            nodes.length == 2 && nodes[0].getSize() == 8 && nodes[1].getSize() == 8 &&
            program.getRegister(nodes[0]).equals(program.getRegister(target.second())) &&
            program.getRegister(nodes[1]).equals(program.getRegister(target.first())), "actual computed join changed");
        Storage rejected = GhidraVariableStorage.stableParameter(program, function, parameter, map, TaskMonitor.DUMMY);
        require(rejected instanceof UnavailableStorage u && u.reason() == OmissionReason.REGISTER_MODIFIED,
            "baseline whole-body rejection changed: " + rejected);
        // First new-feature assertion uses only the existing public API, including on the old JAR.
        var intervals = GhidraVariableStorage.parameterPrefix(program, function, parameter, map, rejected, TaskMonitor.DUMMY);
        require(!intervals.isEmpty(), "missing composite prefix for actual decoded incoming parameter");
        checkIntervals(intervals, 0x1000, 0x1000 + target.boundary(), function.getBody().getMaxAddress().getOffset() + 1,
            List.of(map.dwarfNumbers().get(target.first()), map.dwarfNumbers().get(target.second())), List.of(64, 64));
        require(Arrays.equals(nodes, parameter.getVariableStorage().getVarnodes()), "prefix mutated effective storage");
        Storage local = GhidraVariableStorage.stableLocal(program, function, parameter, map, TaskMonitor.DUMMY);
        require(local instanceof UnavailableStorage u && u.reason() ==
            (custom ? OmissionReason.REGISTER_MODIFIED : OmissionReason.UNASSIGNED), "local behavior changed");
        var model = GhidraTypeGraph.extract(program, List.of(new FunctionSymbol(function.getName(), 0x1000,
            function.getBody().getNumAddresses())), target.map(), 0, TaskMonitor.DUMMY, ignored -> { });
        var modeled = model.variableStorage().variables().stream().filter(v -> v.kind() == VariableKind.PARAMETER).toList();
        require(modeled.size() == 1 && modeled.get(0).locations().size() == 2 &&
            modeled.get(0).locations().get(0).storage().equals(intervals.get(0).storage()) &&
            modeled.get(0).locations().get(1).start() == 0x1000 + target.boundary() &&
            modeled.get(0).locations().get(1).end() == function.getBody().getMaxAddress().getOffset() + 1 &&
            modeled.get(0).locations().get(1).storage() instanceof CompositeStorage migrated &&
            migrated.pieces().size() == 2 && migrated.totalBitSize() == 128 &&
            migrated.pieces().get(0).storage() instanceof RegisterStorage backup &&
            backup.register().dwarfNumber() == (target.map().equals("x86_64") ? 0 : 2) &&
            migrated.pieces().get(1).storage() instanceof RegisterStorage retained &&
            retained.register().dwarfNumber() == map.dwarfNumbers().get(target.second()),
            "public extractor must retain the complete copied piece after the original is overwritten: " + modeled);
        var ranges = intervals.stream().map(i -> new LocationRange(i.start(), i.end(), i.storage(),
            new Evidence(Confidence.USER_DEFINED, "focused actual decoded composite"))).toList();
        var location = new VariableLocation("capture_pair", 0x1000, "value", VariableKind.PARAMETER, 16, ranges);
        var encoded = Dwarf5LocationLists.build(List.of(location), 8, ByteOrder.LITTLE_ENDIAN);
        byte[] data = encoded.section();
        int offset = Math.toIntExact(encoded.offsets().get(location));
        var buffer = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        require(data[offset] == 7 && buffer.getLong(offset + 1) == 0x1000 &&
            buffer.getLong(offset + 9) == 0x1000 + target.boundary(), "location-list address range changed");
        byte[] expression = { (byte) 0x90, map.dwarfNumbers().get(target.first()).byteValue(), (byte) 0x9d, 64, 0,
            (byte) 0x90, map.dwarfNumbers().get(target.second()).byteValue(), (byte) 0x9d, 64, 0 };
        require(data[offset + 17] == 10 && Arrays.equals(expression, Arrays.copyOfRange(data, offset + 18, offset + 28)) &&
            data[offset + 28] == 0 && data.length == offset + 29, "not one complete object-order expression plus unavailable tail");
    }

    private static void checkIntervals(List<StorageInterval> intervals, long start, long boundary, long end,
            List<Integer> numbers, List<Integer> bits) {
        require(intervals.size() == 2 && intervals.get(0).start() == start && intervals.get(0).end() == boundary &&
            intervals.get(1).start() == boundary && intervals.get(1).end() == end, "incorrect prefix/tail boundaries: " + intervals);
        require(intervals.get(0).storage() instanceof CompositeStorage, "prefix is not complete composite");
        var pieces = ((CompositeStorage) intervals.get(0).storage()).pieces();
        require(pieces.size() == numbers.size(), "piece count changed");
        for (int i = 0; i < pieces.size(); i++) {
            require(pieces.get(i).storage() instanceof RegisterStorage r && r.register().dwarfNumber() == numbers.get(i) &&
                r.valueBitOffset() == 0 && r.bitSize() == bits.get(i) && pieces.get(i).bitSize() == bits.get(i), "piece order/slice changed");
        }
        require(intervals.get(1).storage() instanceof UnavailableStorage u && u.reason() == OmissionReason.REGISTER_MODIFIED &&
            u.diagnostic().contains("0x" + Long.toHexString(boundary)), "tail omission changed");
    }

    private static void bigEndianControl() throws Exception {
        // These are controlled straight-line p-code inputs, not a claim of a
        // decoded MIPS prefix: real MIPS return delay slots remain rejected.
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("MIPS:BE:32:default"));
        Object owner = new Object();
        ProgramDB real = new ProgramDB("big-endian-prefix-control", language, language.getDefaultCompilerSpec(), owner);
        try {
            int transaction = real.startTransaction("big-endian piece order");
            try {
                var start = real.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
                real.getMemory().createInitializedBlock("code", start, 16, (byte) 0, TaskMonitor.DUMMY, false);
                var body = new AddressSet(start, start.add(15));
                Function function = real.getFunctionManager().createFunction("pair", start, body, SourceType.USER_DEFINED);
                var pair = new StructureDataType("Pair", 0, real.getDataTypeManager());
                pair.add(new IntegerDataType(real.getDataTypeManager()), "first", null);
                pair.add(new IntegerDataType(real.getDataTypeManager()), "second", null);
                function.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
                function.updateFunction(null, function.getReturn(), Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                    true, SourceType.USER_DEFINED, new ParameterImpl("value", pair, real, SourceType.USER_DEFINED));
                var parameter = function.getParameter(0);
                var a0 = real.getRegister("a0");
                var a1 = real.getRegister("a1");
                var a2 = real.getRegister("a2");
                Varnode[] nodes = parameter.getVariableStorage().getVarnodes();
                require(nodes.length == 2 && real.getRegister(nodes[0]).equals(a0) && real.getRegister(nodes[1]).equals(a1),
                    "real big-endian computed join changed");
                var instructions = List.of(instruction(real, 0x1000, PcodeOp.COPY, null),
                    instruction(real, 0x1004, PcodeOp.COPY, new Varnode(a1.getAddress().add(1), 1)),
                    instruction(real, 0x1008, PcodeOp.COPY, null), instruction(real, 0x100c, PcodeOp.RETURN, null));
                Program program = withInstructions(real, instructions);
                var map = TargetRegisterMap.forTarget("mips");
                Storage rejected = GhidraVariableStorage.stableParameter(program, function, parameter, map, TaskMonitor.DUMMY);
                require(rejected instanceof UnavailableStorage u && u.reason() == OmissionReason.REGISTER_MODIFIED,
                    "big-endian first stable piece masked later write");
                var numbers = List.of(map.dwarfNumbers().get("a0"), map.dwarfNumbers().get("a1"));
                checkIntervals(prefix(program, function, parameter, map, rejected), 0x1000, 0x1008, 0x1010, numbers, List.of(32, 32));
                function.setCustomVariableStorage(true);
                checkIntervals(prefix(program, function, function.getParameter(0), map, rejected), 0x1000, 0x1008, 0x1010, numbers, List.of(32, 32));
                var triple = new VariableStorage(real, nodes[0], nodes[1], new Varnode(a2.getAddress().add(2), 2));
                require(real.getRegister(triple.getVarnodes()[2]) == a2 &&
                    !triple.getVarnodes()[2].getAddress().equals(a2.getAddress()), "BE low-half lookup premise changed");
                checkIntervals(prefix(program, function, resized(parameter, triple, 10), map, rejected),
                    0x1000, 0x1008, 0x1010, List.of(numbers.get(0), numbers.get(1), map.dwarfNumbers().get("a2")), List.of(32, 32, 16));
                reject(withInstructions(real, replace(instructions, 3, proxy(Instruction.class, instructions.get(3),
                    "getDelaySlotDepth", 1))), function, parameter, map, rejected);
            }
            finally {
                real.endTransaction(transaction, true);
            }
        }
        finally {
            real.release(owner);
        }
        System.out.println("composite-register-prefix-control=PASS big-endian-synthetic-body");
    }

    private static void controlled(ProgramDB real, Function actual, Target target) throws Exception {
        var map = TargetRegisterMap.forTarget(target.map());
        var start = actual.getEntryPoint();
        Function function = proxy(Function.class, actual, "getBody", new AddressSet(start, start.add(15)));
        Parameter parameter = actual.getParameter(0);
        Varnode[] nodes = parameter.getVariableStorage().getVarnodes();
        var first = real.getRegister(target.first());
        var second = real.getRegister(target.second());
        Varnode partial = new Varnode(first.getAddress().add(1), 1);
        List<Instruction> instructions = List.of(instruction(real, 0x1000, PcodeOp.COPY, null),
            instruction(real, 0x1004, PcodeOp.COPY, partial), instruction(real, 0x1008, PcodeOp.COPY, null),
            instruction(real, 0x100c, PcodeOp.RETURN, null));
        var program = withInstructions(real, instructions);
        var rejected = new UnavailableStorage(OmissionReason.REGISTER_MODIFIED, "original first-piece diagnostic");
        List<Integer> numbers = List.of(map.dwarfNumbers().get(target.first()), map.dwarfNumbers().get(target.second()));
        checkIntervals(prefix(program, function, parameter, map, rejected), 0x1000, 0x1008, 0x1010, numbers, List.of(64, 64));
        // Later raw-significance piece writes earlier; the first piece also writes, later.
        var both = replace(instructions, 2, instruction(real, 0x1008, PcodeOp.COPY, new Varnode(second.getAddress(), 8)));
        var bothProgram = withInstructions(real, both);
        Storage firstRejection = GhidraVariableStorage.stableParameter(bothProgram, function, parameter, map, TaskMonitor.DUMMY);
        require(firstRejection instanceof UnavailableStorage u && u.diagnostic().contains("1008"), "first-piece omission precedence changed");
        checkIntervals(prefix(bothProgram, function, parameter, map, firstRejection), 0x1000, 0x1008, 0x1010, numbers, List.of(64, 64));
        var entryWrite = replace(instructions, 0, instruction(real, 0x1000, PcodeOp.COPY, partial));
        checkIntervals(prefix(withInstructions(real, entryWrite), function, parameter, map, rejected),
            0x1000, 0x1004, 0x1010, numbers, List.of(64, 64));
        reject(withInstructions(real, replace(instructions, 1, instruction(real, 0x1004, PcodeOp.COPY, null))), function, parameter, map, rejected);
        for (int opcode : new int[] { PcodeOp.CALL, PcodeOp.CALLIND, PcodeOp.BRANCH, PcodeOp.CBRANCH,
                PcodeOp.BRANCHIND, PcodeOp.CALLOTHER, PcodeOp.UNIMPLEMENTED, PcodeOp.STORE }) {
            reject(withInstructions(real, replace(instructions, 2, instruction(real, 0x1008, opcode, null))), function, parameter, map, rejected);
        }
        for (var mutation : Map.<String, Object>of("isLengthOverridden", true, "isFallThroughOverridden", true,
                "getParsedLength", 3, "getLength", 0, "isInDelaySlot", true, "getDelaySlotDepth", 1,
                "getFlowOverride", FlowOverride.CALL, "getFallThrough", start.add(13), "getMaxAddress", start.add(10),
                "getFlowType", RefType.UNCONDITIONAL_CALL).entrySet()) {
            reject(withInstructions(real, replace(instructions, 2, proxy(Instruction.class, instructions.get(2), mutation.getKey(), mutation.getValue()))),
                function, parameter, map, rejected);
        }
        reject(withInstructions(real, instructions.subList(0, 3)), function, parameter, map, rejected);
        reject(withInstructions(real, List.of(instructions.get(0), instructions.get(1), instructions.get(3))), function, parameter, map, rejected);
        reject(withInstructions(real, List.of(instructions.get(0), instructions.get(2), instructions.get(1), instructions.get(3))), function, parameter, map, rejected);
        reject(program, proxy(Function.class, function, "getBody", new AddressSet(start, start.add(19))), parameter, map, rejected);
        var split = new AddressSet(start, start.add(7));
        split.add(start.add(12), start.add(15));
        reject(program, proxy(Function.class, function, "getBody", split), parameter, map, rejected);
        reject(program, proxy(Function.class, function, "getEntryPoint", start.add(4)), parameter, map, rejected);
        for (VariableStorage invalid : new VariableStorage[] { null, VariableStorage.BAD_STORAGE, VariableStorage.UNASSIGNED_STORAGE,
                new DynamicVariableStorage(real, true, nodes) }) {
            reject(program, function, proxy(Parameter.class, parameter, "getVariableStorage", invalid), map, rejected);
        }
        for (int size : new int[] { 0, 15, 17 }) {
            reject(program, function, proxy(Parameter.class, parameter, "getLength", size), map, rejected);
        }
        reject(program, function, proxy(Parameter.class, parameter, "getFormalDataType", null), map, rejected);
        reject(program, function, proxy(Parameter.class, parameter, "getFormalDataType", IntegerDataType.dataType), map, rejected);
        var firstOnly = new TargetRegisterMap("focused", "deliberately missing later piece", Map.of(target.second(), numbers.get(1)));
        var writesFirst = withInstructions(real, replace(instructions, 1,
            instruction(real, 0x1004, PcodeOp.COPY, new Varnode(second.getAddress(), 8))));
        Storage hidden = GhidraVariableStorage.stableParameter(writesFirst, function, parameter, firstOnly, TaskMonitor.DUMMY);
        require(hidden instanceof UnavailableStorage u && u.reason() == OmissionReason.REGISTER_MODIFIED, "missing later map was not hidden by first write");
        reject(writesFirst, function, parameter, firstOnly, hidden);
        var stack = new Varnode(real.getAddressFactory().getStackSpace().getAddress(16), 8);
        // VariableStorage's constructor itself disallows a later LE stack piece.
        // This controlled malformed carrier tests a hidden later piece independently.
        var mixed = malformedStorage(real, nodes, new Varnode[] { nodes[0], stack }, 16);
        var mixedParameter = proxy(Parameter.class, parameter, "getVariableStorage", mixed);
        hidden = GhidraVariableStorage.stableParameter(writesFirst, function, mixedParameter, map, TaskMonitor.DUMMY);
        require(hidden instanceof UnavailableStorage u && u.reason() == OmissionReason.REGISTER_MODIFIED, "mixed later piece was not hidden");
        reject(writesFirst, function, mixedParameter, map, hidden);
        for (Varnode[] malformed : new Varnode[][] { null, new Varnode[] { nodes[0] },
                new Varnode[] { nodes[0], null }, new Varnode[] { nodes[0], nodes[0] },
                new Varnode[] { nodes[0], new Varnode(nodes[1].getAddress(), 0) },
                new Varnode[] { nodes[0], new Varnode(nodes[1].getAddress(), 9) },
                new Varnode[] { nodes[0], new Varnode(nodes[1].getAddress(), 4) },
                new Varnode[] { nodes[0], new Varnode(nodes[1].getAddress().getAddressSpace().getAddress(0x7ffff0), 8) } }) {
            var bad = malformedStorage(real, nodes, malformed, 16);
            reject(writesFirst, function, proxy(Parameter.class, parameter, "getVariableStorage", bad), map, rejected);
        }
        // Revalidate a later mapping's physical extent even when the program returns a register.
        var wrongRegister = proxy(Program.class, writesFirst, "getRegister", second);
        reject(wrongRegister, function, parameter, map, rejected);
        var ram = start.getAddressSpace();
        var constants = real.getAddressFactory().getConstantSpace();
        var selector = new Varnode(constants.getAddress(ram.getSpaceID()), 4);
        var offset = new Varnode(first.getAddress(), ram.getPointerSize());
        var value = new Varnode(constants.getAddress(7), 1);
        var store = new PcodeOp(start.add(8), 0, PcodeOp.STORE, new Varnode[] { selector, offset, value }, null);
        var storeInstruction = proxy(Instruction.class, instructions.get(2), "getPcode", new PcodeOp[] { store });
        checkIntervals(prefix(withInstructions(real, replace(instructions, 2, storeInstruction)), function, parameter, map, rejected),
            0x1000, 0x1008, 0x1010, numbers, List.of(64, 64));
        for (PcodeOp malformed : List.of(
                new PcodeOp(start.add(8), 0, PcodeOp.STORE, new Varnode[] { selector, offset, value }, value),
                new PcodeOp(start.add(8), 0, PcodeOp.STORE, new Varnode[] { offset, offset, value }, null),
                new PcodeOp(start.add(8), 0, PcodeOp.STORE, new Varnode[] { selector, new Varnode(first.getAddress(), 4), value }, null),
                new PcodeOp(start.add(8), 0, PcodeOp.STORE, new Varnode[] {
                    new Varnode(constants.getAddress(first.getAddress().getAddressSpace().getSpaceID()), 4), offset, value }, null))) {
            reject(withInstructions(real, replace(instructions, 2,
                proxy(Instruction.class, instructions.get(2), "getPcode", new PcodeOp[] { malformed }))), function, parameter, map, rejected);
        }
        // A later whole-base alias, even outside the small selected slice, ends the value.
        var smallStorage = new VariableStorage(real, new Varnode(second.getAddress(), 4), new Varnode(first.getAddress(), 4));
        var small = resized(parameter, smallStorage, 8);
        var outsideSlice = replace(instructions, 1, instruction(real, 0x1004, PcodeOp.COPY, new Varnode(first.getAddress().add(7), 1)));
        checkIntervals(prefix(withInstructions(real, outsideSlice), function, small, map, rejected),
            0x1000, 0x1008, 0x1010, numbers, List.of(32, 32));
        if (target.map().equals("x86_64")) {
            var triple = new VariableStorage(real, new Varnode(real.getRegister("RDX").getAddress(), 2), nodes[0], nodes[1]);
            checkIntervals(prefix(program, function, resized(parameter, triple, 18), map, rejected),
                0x1000, 0x1008, 0x1010, List.of(numbers.get(0), numbers.get(1), map.dwarfNumbers().get("RDX")), List.of(64, 64, 16));
            var slices = new VariableStorage(real, real.getRegister("BH"), real.getRegister("AH"));
            var sliceParameter = resized(parameter, slices, 2);
            var sliceBody = replace(instructions, 1, instruction(real, 0x1004, PcodeOp.COPY,
                new Varnode(real.getRegister("RAX").getAddress().add(7), 1)));
            var sliceIntervals = prefix(withInstructions(real, sliceBody), function, sliceParameter, map, rejected);
            require(sliceIntervals.size() == 2 && sliceIntervals.get(0).end() == 0x1008, "high-byte slice prefix missing");
            var pieces = ((CompositeStorage) sliceIntervals.get(0).storage()).pieces();
            require(((RegisterStorage) pieces.get(0).storage()).register().dwarfNumber() == map.dwarfNumbers().get("RAX") &&
                ((RegisterStorage) pieces.get(1).storage()).register().dwarfNumber() == map.dwarfNumbers().get("RBX") &&
                pieces.stream().allMatch(p -> p.bitSize() == 8 && ((RegisterStorage) p.storage()).valueBitOffset() == 8),
                "join normalization changed LSB-relative slices");
        }
        for (OmissionReason reason : OmissionReason.values()) {
            if (reason != OmissionReason.REGISTER_MODIFIED) {
                reject(program, function, parameter, map, new UnavailableStorage(reason, "original reason " + reason));
            }
        }
        // Public reference gate must reject external and offcut entries, including after the boundary.
        for (long destination : new long[] { 0x1008, 0x1009 }) {
            var to = start.getAddressSpace().getAddress(destination);
            var reference = real.getReferenceManager().addMemoryReference(start.add(0x200), to,
                RefType.UNCONDITIONAL_JUMP, SourceType.USER_DEFINED, 0);
            reject(program, function, parameter, map, rejected);
            real.getReferenceManager().delete(reference);
        }
        var marker = new CancelledException("focused cancellation");
        int[] totalPolls = { 0 };
        var counting = new TaskMonitorAdapter(true) {
            @Override public void checkCancelled() { totalPolls[0]++; }
        };
        require(!GhidraVariableStorage.parameterPrefix(program, function, parameter, map, rejected, counting).isEmpty(),
            "cancellation control baseline failed");
        require(totalPolls[0] > 20, "whole proof did not poll cancellation");
        for (int after = 1; after <= totalPolls[0]; after++) {
            final int stop = after;
            var monitor = new TaskMonitorAdapter(true) {
                int polls;
                @Override public void checkCancelled() throws CancelledException {
                    if (++polls == stop) { throw marker; }
                }
            };
            try {
                GhidraVariableStorage.parameterPrefix(program, function, parameter, map, rejected, monitor);
                throw new AssertionError("cancelled composite proof completed at poll " + after);
            }
            catch (CancelledException expected) {
                require(expected == marker, "cancellation replaced");
            }
        }
    }

    private static List<StorageInterval> prefix(Program program, Function function, Parameter parameter,
            TargetRegisterMap map, Storage rejected) throws Exception {
        return GhidraVariableStorage.parameterPrefix(program, function, parameter, map, rejected, TaskMonitor.DUMMY);
    }

    private static VariableStorage malformedStorage(Program program, Varnode[] valid, Varnode[] reported, int bytes)
            throws Exception {
        return new VariableStorage(program, valid) {
            @Override public Varnode[] getVarnodes() { return reported; }
            @Override public int size() { return bytes; }
        };
    }

    private static Parameter resized(Parameter parameter, VariableStorage storage, int bytes) {
        DataType formal = new StructureDataType("ControlledSize" + bytes, bytes);
        return proxy(Parameter.class, proxy(Parameter.class, proxy(Parameter.class, parameter,
            "getVariableStorage", storage), "getLength", bytes), "getFormalDataType", formal);
    }

    private static void reject(Program program, Function function, Parameter parameter,
            TargetRegisterMap map, Storage rejected) throws Exception {
        String before = rejected.toString();
        require(prefix(program, function, parameter, map, rejected).isEmpty(), "unsafe prefix accepted");
        require(before.equals(rejected.toString()), "failed refinement changed original omission");
    }

    private static Instruction instruction(Program program, long address, int opcode, Varnode output) {
        var at = program.getAddressFactory().getDefaultAddressSpace().getAddress(address);
        boolean returns = opcode == PcodeOp.RETURN;
        PcodeOp op = new PcodeOp(at, 0, opcode, new Varnode[0], output);
        return (Instruction) Proxy.newProxyInstance(Instruction.class.getClassLoader(), new Class<?>[] { Instruction.class },
            (proxy, method, arguments) -> switch (method.getName()) {
                case "getAddress" -> at;
                case "getMaxAddress" -> at.add(3);
                case "getLength", "getParsedLength" -> 4;
                case "isLengthOverridden", "isFallThroughOverridden", "isInDelaySlot" -> false;
                case "getDelaySlotDepth" -> 0;
                case "getFlowOverride" -> FlowOverride.NONE;
                case "getFallThrough" -> returns ? null : at.add(4);
                case "getFlows", "getDefaultFlows" -> new ghidra.program.model.address.Address[0];
                case "getFlowType" -> returns ? RefType.TERMINATOR : RefType.FALL_THROUGH;
                case "getPcode" -> new PcodeOp[] { op };
                case "getResultObjects" -> new Object[0];
                default -> throw new AssertionError("unexpected instruction API " + method);
            });
    }

    private static Program withInstructions(Program real, List<Instruction> instructions) {
        Listing listing = (Listing) Proxy.newProxyInstance(Listing.class.getClassLoader(), new Class<?>[] { Listing.class },
            (proxy, method, args) -> {
                if (!method.getName().equals("getInstructions")) { throw new AssertionError("unexpected listing API " + method); }
                Iterator<Instruction> iterator = instructions.iterator();
                return new InstructionIterator() {
                    public boolean hasNext() { return iterator.hasNext(); }
                    public Instruction next() { return iterator.next(); }
                    public Iterator<Instruction> iterator() { return this; }
                };
            });
        return proxy(Program.class, real, "getListing", listing);
    }

    private static List<Instruction> replace(List<Instruction> source, int index, Instruction replacement) {
        var result = new ArrayList<>(source);
        result.set(index, replacement);
        return List.copyOf(result);
    }

    private static <T> T proxy(Class<T> type, T original, String name, Object value) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] { type }, (proxy, method, args) -> {
            if (method.getName().equals(name)) { return value; }
            try { return method.invoke(original, args); }
            catch (InvocationTargetException error) { throw error.getCause(); }
        }));
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) { throw new AssertionError(message); }
    }
}
