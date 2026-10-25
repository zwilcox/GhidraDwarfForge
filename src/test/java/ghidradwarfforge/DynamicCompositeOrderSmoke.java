package ghidradwarfforge;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import db.DBHandle;
import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.data.OpenMode;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.function.FunctionDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.DynamicVariableStorage;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.AddressXML;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.XmlEncode;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.dwarf.DwarfLocationExpression;
import ghidradwarfforge.dwarf.DwarfLocationExpression.Expression;
import ghidradwarfforge.dwarf.DwarfLocationExpression.GenericOperation;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.Confidence;
import ghidradwarfforge.locations.VariableStorageModel.CompositeStorage;
import ghidradwarfforge.locations.VariableStorageModel.Evidence;
import ghidradwarfforge.locations.VariableStorageModel.LocationRange;
import ghidradwarfforge.locations.VariableStorageModel.OmissionReason;
import ghidradwarfforge.locations.VariableStorageModel.Piece;
import ghidradwarfforge.locations.VariableStorageModel.RegisterStorage;
import ghidradwarfforge.locations.VariableStorageModel.Storage;
import ghidradwarfforge.locations.VariableStorageModel.UnavailableStorage;
import ghidradwarfforge.locations.VariableStorageModel.VariableKind;
import ghidradwarfforge.locations.VariableStorageModel.VariableLocation;

/** Real computed joins, explicit custom storage and immutable database reopening. */
public final class DynamicCompositeOrderSmoke {
    private record Target(String language, String map, String code, List<String> registers,
            int wordBytes) {
    }

    private static int checks;

    private DynamicCompositeOrderSmoke() {
    }

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (Target target : List.of(
                new Target("ARM:LE:32:v8", "arm", "00f020e31eff2fe1", List.of("r0", "r1", "r2"), 4),
                new Target("MIPS:BE:32:default", "mips", "0000000003e0000800000000", List.of("a0", "a1", "a2"), 4),
                new Target("MIPS:LE:32:default", "mipsel", "000000000800e00300000000", List.of("a0", "a1", "a2"), 4),
                new Target("x86:LE:64:default", "x86_64", "90c3", List.of("RDI", "RSI"), 8),
                new Target("AARCH64:LE:64:v8A", "aarch64", "1f2003d5c0035fd6", List.of("x0", "x1"), 8))) {
            check(target);
        }
        System.out.println("dynamic-composite-order-smoke=PASS checks=" + checks);
    }

    private static void check(Target target) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(target.language()));
        var compiler = target.map().equals("x86_64")
            ? language.getCompilerSpecByID(new CompilerSpecID("gcc")) : language.getDefaultCompilerSpec();
        Object owner = new Object();
        ProgramDB program = new ProgramDB("computed-composite-order", language, compiler, owner);
        var directory = Files.createTempDirectory("forge-composite-order-");
        var saved = directory.resolve("program.db");
        try {
            int transaction = program.startTransaction("actual computed joins and explicit storage");
            try {
                var pair = structure(program, "Pair", 2);
                var triple = structure(program, "Triple", 3);
                create(program, target, 0x1000, "pair_argument", pair);
                create(program, target, 0x1100, "wide_argument", new LongLongDataType(program.getDataTypeManager()));
                create(program, target, 0x1200, "triple_argument", triple);
                observeAll(program, target);
                conversionControls(program, target, pair, triple);
                explicitControls(program, target);
                if (target.wordBytes() == 4) {
                    rejectionControls(program, at(program, 0x1000), target);
                }
                if (target.map().equals("arm")) {
                    precedenceControls(program, target, pair);
                }
            }
            finally {
                program.endTransaction(transaction, true);
            }
            program.getDBHandle().saveAs(saved.toFile(), false, TaskMonitor.DUMMY);
            byte[] before = digest(Files.readAllBytes(saved));
            var mtime = Files.getLastModifiedTime(saved);
            Object reader = new Object();
            DBHandle handle = new DBHandle(saved.toFile());
            ProgramDB reopened = null;
            try {
                reopened = new ProgramDB(handle, OpenMode.IMMUTABLE, TaskMonitor.DUMMY, reader);
                observeAll(reopened, target);
                observeConverted(reopened, target);
                observeCustom(reopened, target);
            }
            finally {
                if (reopened != null) {
                    reopened.release(reader);
                }
                else {
                    handle.close();
                }
            }
            require(Arrays.equals(before, digest(Files.readAllBytes(saved))) &&
                mtime.equals(Files.getLastModifiedTime(saved)), "immutable reopen modified database");
            System.out.println("dynamic-composite-order-target=PASS " + target.language());
        }
        finally {
            program.release(owner);
            Files.deleteIfExists(saved);
            Files.deleteIfExists(directory);
        }
    }

    private static DataType structure(ProgramDB program, String name, int fields) {
        var type = new StructureDataType(name, 0, program.getDataTypeManager());
        for (int i = 0; i < fields; i++) {
            type.add(new IntegerDataType(program.getDataTypeManager()), "field" + i, null);
        }
        require(type.getLength() == fields * 4, "fixture structure size changed");
        for (int i = 0; i < fields; i++) {
            require(type.getComponent(i).getOffset() == i * 4, "fixture member offset changed");
        }
        return type;
    }

    private static Function create(ProgramDB program, Target target, long entry, String name,
            DataType type) throws Exception {
        byte[] code = HexFormat.of().parseHex(target.code());
        var start = program.getAddressFactory().getDefaultAddressSpace().getAddress(entry);
        var body = new AddressSet(start, start.add(code.length - 1));
        var block = program.getMemory().createInitializedBlock(name, start, code.length,
            (byte) 0, TaskMonitor.DUMMY, false);
        block.setExecute(true);
        program.getMemory().setBytes(start, code);
        if (target.map().equals("arm")) {
            program.getProgramContext().setValue(program.getRegister("TMode"), start,
                body.getMaxAddress(), BigInteger.ZERO);
        }
        require(new DisassembleCommand(start, body, true).applyTo(program, TaskMonitor.DUMMY), "fixture did not decode");
        var function = program.getFunctionManager().createFunction(name, start, body, SourceType.USER_DEFINED);
        function.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
        function.updateFunction(null, function.getReturn(), Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
            true, SourceType.USER_DEFINED, new ParameterImpl("value", type, program, SourceType.USER_DEFINED));
        return function;
    }

    private static Function at(ProgramDB program, long address) {
        return program.getFunctionManager().getFunctionAt(program.getAddressFactory().getDefaultAddressSpace().getAddress(address));
    }

    private static void observeAll(ProgramDB program, Target target) throws Exception {
        observe(program, at(program, 0x1000), target, 8, false);
        observe(program, at(program, 0x1100), target, 8, false);
        observe(program, at(program, 0x1200), target, 12, false);
    }

    private static void conversionControls(ProgramDB program, Target target, DataType pair, DataType triple) throws Exception {
        DataType[] types = { pair, new LongLongDataType(program.getDataTypeManager()), triple };
        for (int i = 0; i < types.length; i++) {
            Function function = create(program, target, 0x4000 + i * 0x100, "converted_" + i, types[i]);
            observe(program, function, target, types[i].getLength(), false);
            Varnode[] before = function.getParameter(0).getVariableStorage().getVarnodes();
            String signature = function.getPrototypeString(false, false);
            function.setCustomVariableStorage(true);
            require(Arrays.equals(before, function.getParameter(0).getVariableStorage().getVarnodes()) &&
                signature.equals(function.getPrototypeString(false, false)), "conversion changed signature or pieces");
            observe(program, function, target, types[i].getLength(), true);
        }
    }

    private static void observeConverted(ProgramDB program, Target target) throws Exception {
        observe(program, at(program, 0x4000), target, 8, true);
        observe(program, at(program, 0x4100), target, 8, true);
        observe(program, at(program, 0x4200), target, 12, true);
    }

    private static void checkSerialization(Varnode[] nodes) throws Exception {
        var encoder = new XmlEncode(false);
        AddressXML.encode(encoder, nodes, 0);
        StringBuilder expected = new StringBuilder("<addr space=\"join\"");
        for (int i = 0; i < nodes.length; i++) {
            expected.append(" piece").append(i + 1).append("=\"").append(nodes[i].encodePiece()).append("\"");
        }
        expected.append("/>");
        require(encoder.toString().equals(expected.toString()), "actual join serialization changed significance order");
    }

    private static void observe(ProgramDB program, Function function, Target target, int bytes, boolean custom) throws Exception {
        Parameter parameter = function.getParameter(0);
        VariableStorage effective = parameter.getVariableStorage();
        require(function instanceof FunctionDB && function.hasCustomVariableStorage() == custom &&
            function.getProgram() == program && parameter.getFunction() == function &&
            function.getParameter(parameter.getOrdinal()) == parameter && !parameter.isAutoParameter(),
            "actual attached computed parameter origin changed");
        require((custom ? effective.getClass() == VariableStorage.class : effective instanceof DynamicVariableStorage) &&
            effective.getProgramArchitecture() == program && effective == parameter.getVariableStorage() &&
            parameter.hasAssignedStorage() == custom && effective.isValid() &&
            !effective.isBadStorage() && !effective.isUnassignedStorage() && !effective.isForcedIndirect() && effective.size() == bytes,
            "effective dynamic storage is not exact and valid");
        int count = (bytes + target.wordBytes() - 1) / target.wordBytes();
        List<Integer> bits = new ArrayList<>();
        List<Integer> numbers = new ArrayList<>();
        var map = TargetRegisterMap.forTarget(target.map());
        for (int i = 0; i < count; i++) {
            bits.add(Math.min(target.wordBytes(), bytes - i * target.wordBytes()) * 8);
            numbers.add(map.dwarfNumbers().get(target.registers().get(i)));
        }
        Varnode[] nodes = effective.getVarnodes();
        require(nodes.length == count, "computed fixture has unexpected piece count: " + effective);
        for (int i = 0; i < count; i++) {
            int objectIndex = program.getLanguage().isBigEndian() ? i : count - 1 - i;
            require(nodes[i].getSize() * 8 == bits.get(objectIndex), "computed join size order changed: " + effective);
            var register = program.getRegister(nodes[i]);
            require(register != null && register.getBaseRegister() == program.getRegister(target.registers().get(objectIndex)).getBaseRegister(),
                "computed join significance order changed: " + effective);
        }
        Storage actual = GhidraVariableStorage.stableParameter(program, function, parameter, map, TaskMonitor.DUMMY);
        if (count == 1) {
            require(actual instanceof RegisterStorage register && register.register().dwarfNumber() == numbers.get(0) &&
                register.bitSize() == bytes * 8, "single register behavior changed");
        }
        else {
            checkSerialization(nodes);
            checkPieces(actual, numbers, bits, custom ? "converted custom pieces are not in object memory order" :
                "computed pieces are not in object memory order");
            checkExpression((CompositeStorage) actual, bytes, numbers, bits);
        }
        require(Arrays.equals(nodes, effective.getVarnodes()), "normalization mutated Ghidra storage");
    }

    private static void checkPieces(Storage storage, List<Integer> numbers, List<Integer> bits, String message) {
        require(storage instanceof CompositeStorage, message + ": " + storage);
        var pieces = ((CompositeStorage) storage).pieces();
        require(pieces.size() == numbers.size(), message);
        for (int i = 0; i < pieces.size(); i++) {
            require(pieces.get(i).storage() instanceof RegisterStorage register &&
                register.register().dwarfNumber() == numbers.get(i) && register.valueBitOffset() == 0 &&
                register.bitSize() == bits.get(i) && pieces.get(i).bitSize() == bits.get(i), message + ": " + pieces);
        }
    }

    private static void checkExpression(CompositeStorage storage, int bytes, List<Integer> numbers, List<Integer> bits) {
        var location = new VariableLocation("function", 0x1000, "value", VariableKind.PARAMETER, bytes,
            List.of(new LocationRange(0x1000, 0x1004, storage,
                new Evidence(Confidence.USER_DEFINED, "actual computed parameter"))));
        var expression = DwarfLocationExpression.planStable(location);
        require(expression instanceof Expression, "composite expression omitted");
        List<GenericOperation> expected = new ArrayList<>();
        for (int i = 0; i < numbers.size(); i++) {
            expected.add(new GenericOperation(DwarfLocationExpression.DW_OP_REGX, numbers.get(i), 0));
            expected.add(new GenericOperation(DwarfLocationExpression.DW_OP_BIT_PIECE, bits.get(i), 0));
        }
        require(((Expression) expression).operations().equals(expected), "emitter changed declared object order");
    }

    private static Varnode[] explicitNodes(ProgramDB program, Target target, int index) {
        if (index == 1 && target.wordBytes() == 4) {
            return new Varnode[] {
                new Varnode(program.getRegister(target.registers().get(2)).getAddress(), 4),
                new Varnode(program.getRegister(target.registers().get(1)).getAddress(), 4),
                new Varnode(program.getRegister(target.registers().get(0)).getAddress(), 4) };
        }
        return new Varnode[] {
            new Varnode(program.getRegister(target.registers().get(1)).getAddress(), 4),
            new Varnode(program.getRegister(target.registers().get(0)).getAddress(), index == 1 ? 8 : 4) };
    }

    private static void explicitControls(ProgramDB program, Target target) throws Exception {
        for (int i = 0; i < 2; i++) {
            DataType type = i == 0 ? new LongLongDataType(program.getDataTypeManager()) : structure(program, "ExplicitTriple", 3);
            Function function = create(program, target, 0x2000 + i * 0x200, "explicit_custom_" + i, type);
            var storage = new VariableStorage(program, explicitNodes(program, target, i));
            function.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.USER_DEFINED,
                new ParameterImpl("custom_value", type, storage, program, SourceType.USER_DEFINED));
            require(function.getParameter(0) != null, "explicit custom parameter was not installed");
            Function localFunction = create(program, target, 0x2100 + i * 0x200, "explicit_local_" + i, type);
            localFunction.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.USER_DEFINED);
            localFunction.addLocalVariable(new LocalVariableImpl("custom_local", 0, type, storage, false, program,
                SourceType.USER_DEFINED), SourceType.USER_DEFINED);
        }
        observeCustom(program, target);
        // Direct neutral-model pieces already describe object order, regardless
        // of Ghidra serialization or target endianness. Do not normalize them.
        var map = TargetRegisterMap.forTarget(target.map());
        var direct = new CompositeStorage(List.of(new Piece(map.register(target.registers().get(1), 0, 32), 32),
            new Piece(map.register(target.registers().get(0), 0, 32), 32)));
        checkExpression(direct, 8, List.of(map.dwarfNumbers().get(target.registers().get(1)),
            map.dwarfNumbers().get(target.registers().get(0))), List.of(32, 32));
    }

    private static void observeCustom(ProgramDB program, Target target) throws Exception {
        var map = TargetRegisterMap.forTarget(target.map());
        for (int i = 0; i < 2; i++) {
            Function function = at(program, 0x2000 + i * 0x200);
            require(function.hasCustomVariableStorage(), "explicit custom flag lost");
            Varnode[] nodes = explicitNodes(program, target, i);
            require(Arrays.equals(nodes, function.getParameter(0).getVariableStorage().getVarnodes()), "explicit storage changed");
            checkSerialization(nodes);
            List<Integer> numbers = new ArrayList<>();
            List<Integer> bits = new ArrayList<>();
            // Native Ghidra JoinRecord consumes piece1 as most significant.
            // Object bytes on LE start at the last significance piece.
            for (int j = 0; j < nodes.length; j++) {
                Varnode node = nodes[program.getLanguage().isBigEndian() ? j : nodes.length - 1 - j];
                numbers.add(map.dwarfNumbers().get(program.getRegister(node).getBaseRegister().getName()));
                bits.add(node.getSize() * 8);
            }
            Storage actual = GhidraVariableStorage.stableParameter(program, function, function.getParameter(0), map, TaskMonitor.DUMMY);
            checkPieces(actual, numbers, bits, "explicit custom parameter is not in object memory order");
            checkExpression((CompositeStorage) actual, i == 0 ? 8 : 12, numbers, bits);
            Function localFunction = at(program, 0x2100 + i * 0x200);
            var local = Arrays.stream(localFunction.getLocalVariables()).filter(v -> v.getName().equals("custom_local")).findFirst().orElseThrow();
            checkPieces(GhidraVariableStorage.stableLocal(program, localFunction, local, map, TaskMonitor.DUMMY),
                numbers, bits, "explicit local is not in object memory order");
            require(Arrays.equals(nodes, local.getVariableStorage().getVarnodes()), "local normalization mutated storage");
        }
    }

    private static void rejectionControls(ProgramDB program, Function function, Target target) throws Exception {
        var map = TargetRegisterMap.forTarget(target.map());
        Parameter real = function.getParameter(0);
        VariableStorage storage = real.getVariableStorage();
        for (VariableStorage invalid : new VariableStorage[] { null, VariableStorage.UNASSIGNED_STORAGE, VariableStorage.BAD_STORAGE,
                new DynamicVariableStorage(program, true, storage.getVarnodes()) }) {
            var parameter = proxy(Parameter.class, real, "getVariableStorage", invalid);
            omitted(GhidraVariableStorage.stableParameter(program, function, parameter, map, TaskMonitor.DUMMY),
                invalid == null || invalid.isUnassignedStorage() ? OmissionReason.UNASSIGNED : OmissionReason.UNSUPPORTED_STORAGE);
        }
        var wrongSize = proxy(Parameter.class, real, "getLength", 4);
        omitted(GhidraVariableStorage.stableParameter(program, function, wrongSize, map, TaskMonitor.DUMMY), OmissionReason.UNSUPPORTED_STORAGE);
        var stack = program.getAddressFactory().getStackSpace();
        var register = storage.getVarnodes()[0];
        var memory = new Varnode(stack.getAddress(16), 4);
        var mixedNodes = program.getLanguage().isBigEndian() ? new Varnode[] { register, memory } : new Varnode[] { memory, register };
        var mixed = new VariableStorage(program, mixedNodes);
        var mixedParameter = proxy(Parameter.class, real, "getVariableStorage", mixed);
        omitted(GhidraVariableStorage.stableParameter(program, function, mixedParameter, map, TaskMonitor.DUMMY), OmissionReason.UNSUPPORTED_STORAGE);
        var marker = new CancelledException("composite cancellation");
        var polls = new AtomicInteger();
        var monitor = new TaskMonitorAdapter(true) {
            @Override
            public void checkCancelled() throws CancelledException {
                polls.incrementAndGet();
                throw marker;
            }
        };
        try {
            GhidraVariableStorage.stableParameter(program, function, real, map, monitor);
            throw new AssertionError("composite scan ignored cancellation");
        }
        catch (CancelledException expected) {
            require(expected == marker && polls.get() == 1, "cancellation identity or first poll changed");
        }
    }

    private static void precedenceControls(ProgramDB program, Target target, DataType pair) throws Exception {
        var map = TargetRegisterMap.forTarget(target.map());
        // Real decoded MOVs write both pieces. The original significance-order
        // proof must still report r1 first; normalization happens only on success.
        Target writes = new Target(target.language(), target.map(), "0010a0e30000a0e31eff2fe1", target.registers(), 4);
        Function modified = create(program, writes, 0x3000, "both_pieces_modified", pair);
        Parameter parameter = modified.getParameter(0);
        var original = parameter.getVariableStorage().getVarnodes();
        require(program.getRegister(original[0]).getName().equals("r1"), "precedence control lost significance order");
        Storage rejected = GhidraVariableStorage.stableParameter(program, modified, parameter, map, TaskMonitor.DUMMY);
        omitted(rejected, OmissionReason.REGISTER_MODIFIED);
        require(((UnavailableStorage) rejected).diagnostic().contains("register r1 at 00003000"),
            "normalization changed first modified-piece diagnostic: " + rejected);
        var detached = new ParameterImpl("detached", pair, parameter.getVariableStorage(), program);
        require(rejected.equals(GhidraVariableStorage.stableParameter(program, modified, detached, map, TaskMonitor.DUMMY)),
            "detached storage changed known register-write omission");
        require(GhidraVariableStorage.parameterPrefix(program, modified, parameter, map, rejected, TaskMonitor.DUMMY).isEmpty(),
            "composite change fabricated a partial register-copy prefix");
        for (var item : List.of(
                new Object[] { "000000eb1eff2fe1", 0x3100L, "compound_call", OmissionReason.CALL_CLOBBERED },
                new Object[] { "000000ef1eff2fe1", 0x3200L, "compound_opaque", OmissionReason.UNKNOWN_LIFETIME })) {
            Target code = new Target(target.language(), target.map(), (String) item[0], target.registers(), 4);
            Function function = create(program, code, (Long) item[1], (String) item[2], pair);
            Parameter actual = function.getParameter(0);
            Storage omission = GhidraVariableStorage.stableParameter(program, function, actual, map, TaskMonitor.DUMMY);
            omitted(omission, (OmissionReason) item[3]);
            var unowned = new ParameterImpl("detached", pair, actual.getVariableStorage(), program);
            require(omission.equals(GhidraVariableStorage.stableParameter(program, function, unowned, map, TaskMonitor.DUMMY)),
                "storage conversion replaced existing call/opaque diagnostic");
        }
    }

    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type, T original, String name, Object value) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] { type }, (proxy, method, arguments) -> {
            if (method.getName().equals(name)) {
                return value;
            }
            try {
                return method.invoke(original, arguments);
            }
            catch (InvocationTargetException failure) {
                throw failure.getCause();
            }
        });
    }

    private static void omitted(Storage value, OmissionReason reason) {
        require(value instanceof UnavailableStorage unavailable && unavailable.reason() == reason,
            "unexpected omission: " + value + "; expected " + reason);
    }

    private static byte[] digest(byte[] value) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(value);
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
