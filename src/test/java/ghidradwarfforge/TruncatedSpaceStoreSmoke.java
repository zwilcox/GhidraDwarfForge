package ghidradwarfforge;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.UnsignedLongLongDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.SleighLanguageDescription;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.OmissionReason;
import ghidradwarfforge.locations.VariableStorageModel.Storage;
import ghidradwarfforge.locations.VariableStorageModel.UnavailableStorage;

/** Real decoded STOREs plus controlled malformed metadata; no native producer. */
public final class TruncatedSpaceStoreSmoke {
    private static int checks;

    private TruncatedSpaceStoreSmoke() {
    }

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (boolean big : List.of(true, false)) {
            try (Fixture fixture = fixture(big, true)) {
                truncated(fixture, big);
            }
            try (Fixture fixture = fixture(big, false)) {
                ordinary(fixture);
            }
        }
        System.out.println("truncated-space-store-smoke=PASS checks=" + checks);
    }

    private static void truncated(Fixture fixture, boolean big) throws Exception {
        ProgramDB program = fixture.program();
        var language = program.getLanguage();
        var space = program.getAddressFactory().getDefaultAddressSpace();
        require(language instanceof SleighLanguage &&
            language.getLanguageDescription() instanceof SleighLanguageDescription,
            "fixture is not a real loaded Sleigh language");
        var description = (SleighLanguageDescription) language.getLanguageDescription();
        require(description.getTruncatedSpaceNames().contains(space.getName()) &&
            description.getTruncatedSpaceSize(space.getName()) == 4 &&
            space.getPointerSize() == 4 && space.getSize() == 32 &&
            space.getAddressableUnitSize() == 1 && space.getType() == AddressSpace.TYPE_RAM &&
            !space.isOverlaySpace() && space.getPhysicalSpace() == space &&
            language.getAddressFactory().getAddressSpace(space.getSpaceID()) == space &&
            language.getAddressFactory().getAddressSpace(space.getName()) == space,
            "real truncated-space metadata changed");
        PcodeOp store = store(fixture);
        require(store.getInput(1).getSize() == 8 && store.getInput(2).getSize() == 8 &&
            store.getNumInputs() == 3 && store.getOutput() == null &&
            store.getInput(0).isConstant() &&
            (int) store.getInput(0).getOffset() == space.getSpaceID(),
            "real decoded sd does not exercise widened address into truncated RAM");
        // Exact old exporter fails here, after proving this is actual decoded p-code.
        require(!GhidraVariableStorage.unprovenStore(program, store),
            "actual truncated RAM STORE was rejected");
        require(!fixture.function().hasCustomVariableStorage() &&
            !fixture.function().getParameter(0).hasAssignedStorage() &&
            fixture.function().getParameter(0).getVariableStorage().isValid() &&
            fixture.function().getParameter(0).getVariableStorage().size() == 8,
            "wide parameter did not use computed storage");
        require(stable(fixture, program).available(), "decoded store lost stable wide parameter");
        var map = TargetRegisterMap.forTarget(big ? "mips" : "mipsel");
        var local = new LocalVariableImpl("local_copy", 0, UnsignedLongLongDataType.dataType,
            program.getRegister("a0"), program);
        require(GhidraVariableStorage.stableLocal(program, fixture.function(), local, map,
            TaskMonitor.DUMMY).available(), "declared local register proof changed");
        Variable unassigned = decorate(Variable.class, local, Map.of("hasAssignedStorage", false));
        reason(GhidraVariableStorage.stableLocal(program, fixture.function(), unassigned, map,
            TaskMonitor.DUMMY), OmissionReason.UNASSIGNED);

        for (int width : new int[] { 4, 5, 6, 7, 8 }) {
            require(!GhidraVariableStorage.unprovenStore(program, offsetWidth(store, width)),
                "bounded known-space offset rejected: " + width);
        }
        for (int width : new int[] { 0, 1, 2, 3, 9, 16 }) {
            reject(program, offsetWidth(store, width), "unsupported offset width " + width);
        }
        malformed(fixture, store);
        metadata(fixture, store);
        precedence(fixture, store);
        var marker = new CancelledException("truncated STORE cancellation");
        var polls = new AtomicInteger();
        var monitor = new TaskMonitorAdapter(true) {
            @Override
            public void checkCancelled() throws CancelledException {
                polls.incrementAndGet();
                throw marker;
            }
        };
        try {
            GhidraVariableStorage.stableParameter(program, fixture.function(),
                fixture.function().getParameter(0), map, monitor);
            throw new AssertionError("truncated STORE scan ignored cancellation");
        }
        catch (CancelledException expected) {
            require(expected == marker && polls.get() == 1, "cancellation identity/phase changed");
        }
        System.out.println("truncated-space-store-target=PASS " + language.getLanguageID());
    }

    private static void ordinary(Fixture fixture) throws Exception {
        var program = fixture.program();
        PcodeOp store = store(fixture);
        require(store.getInput(1).getSize() == 4 &&
            program.getAddressFactory().getDefaultAddressSpace().getPointerSize() == 4,
            "ordinary STORE no longer matches memory width");
        require(!GhidraVariableStorage.unprovenStore(program, store),
            "ordinary equal-width STORE changed");
        for (int width : new int[] { 0, 1, 2, 3, 5, 6, 7, 8, 9, 16 }) {
            reject(program, offsetWidth(store, width), "nontruncated mismatch " + width);
        }
        require(stable(fixture, program).available(), "ordinary parameter lost stable location");
        var changed = decorate(Instruction.class, fixture.instructions().get(0),
            Map.of("getPcode", new PcodeOp[] { offsetWidth(store, 8) }));
        unknown(stable(fixture, withInstructions(program, List.of(changed))));
    }

    private static void malformed(Fixture fixture, PcodeOp store) {
        Program program = fixture.program();
        Varnode[] good = store.getInputs();
        for (int count : new int[] { 0, 1, 2, 4 }) {
            Varnode[] inputs = new Varnode[count];
            for (int i = 0; i < count; i++) {
                inputs[i] = good[Math.min(i, 2)];
            }
            reject(program, operation(store, PcodeOp.STORE, inputs, null), "input count " + count);
        }
        for (int index = 0; index < 3; index++) {
            Varnode[] inputs = good.clone();
            inputs[index] = null;
            reject(program, operation(store, PcodeOp.STORE, inputs, null), "null input " + index);
        }
        reject(program, operation(store, PcodeOp.STORE, good, good[2]), "output on STORE");
        reject(program, operation(store, PcodeOp.STORE,
            new Varnode[] { good[1], good[1], good[2] }, null), "nonconstant selector");
        reject(program, operation(store, PcodeOp.STORE,
            new Varnode[] { good[0], good[1], new Varnode(good[2].getAddress(), 0) }, null),
            "zero value size");
        var factory = program.getAddressFactory();
        for (long id : new long[] { 0x100000000L, 0x100000001L, 0x7fffffffL }) {
            require(factory.getAddressSpace((int) id) == null || id > 0xffffffffL,
                "chosen bad selector is a real address space");
            reject(program, selector(store, factory, id), "invalid selector " + id);
        }
        for (AddressSpace destination : List.of(factory.getConstantSpace(), factory.getUniqueSpace(),
                factory.getRegisterSpace(), AddressSpace.OTHER_SPACE, AddressSpace.EXTERNAL_SPACE)) {
            PcodeOp mismatched = offsetWidth(selector(store, factory, destination.getSpaceID()),
                destination.getPointerSize() == 8 ? 7 : 8);
            require(mismatched.getInput(1).getSize() != destination.getPointerSize(),
                "negative must not exercise the preserved equal-width path");
            reject(program, mismatched,
                "non-RAM mismatched destination " + destination.getName());
        }
        require(!GhidraVariableStorage.unprovenStore(program,
            operation(store, PcodeOp.COPY, good, null)), "non-STORE classification changed");
    }

    private static void metadata(Fixture fixture, PcodeOp store) {
        var program = fixture.program();
        var actual = program.getAddressFactory().getDefaultAddressSpace();
        AddressFactory realFactory = program.getAddressFactory();
        // Identity is stricter than equal ID/name/type/size/unit metadata.
        AddressSpace clone = new GenericAddressSpace(actual.getName(), actual.getSize(),
            actual.getAddressableUnitSize(), actual.getType(), actual.getUnique());
        require(clone != actual && clone.getSpaceID() == actual.getSpaceID(),
            "clone must have equal metadata but distinct identity");
        for (AddressSpace replacement : List.of(clone,
                decorate(AddressSpace.class, actual, Map.of("isOverlaySpace", true)),
                decorate(AddressSpace.class, actual, Map.of("getType", AddressSpace.TYPE_CODE)),
                decorate(AddressSpace.class, actual, Map.of("getSize", 16)),
                decorate(AddressSpace.class, actual, Map.of("getPointerSize", 2)),
                decorate(AddressSpace.class, actual, Map.of("getAddressableUnitSize", 2)),
                decorate(AddressSpace.class, actual, Map.of("getAddressableUnitSize", 0)),
                decorate(AddressSpace.class, actual, Map.of("getName", "forged")),
                decorate(AddressSpace.class, actual, Map.of("getPhysicalSpace", clone)))) {
            AddressFactory factory = replacedFactory(realFactory, actual, replacement, true);
            reject(decorate(Program.class, program, Map.of("getAddressFactory", factory)), store,
                "foreign or altered Program space");
        }
        AddressFactory nameMismatch = replacedFactory(realFactory, actual, clone, false);
        reject(decorate(Program.class, program, Map.of("getAddressFactory", nameMismatch)), store,
            "Program name lookup differs from ID lookup");
        Language forged = decorate(Language.class, program.getLanguage(), Map.of());
        reject(decorate(Program.class, program, Map.of("getLanguage", forged)), store,
            "interface proxy must not forge a loaded Sleigh language");
    }

    private static AddressFactory replacedFactory(AddressFactory real, AddressSpace actual,
            AddressSpace replacement, boolean byId) {
        return (AddressFactory) Proxy.newProxyInstance(AddressFactory.class.getClassLoader(),
            new Class<?>[] { AddressFactory.class }, (proxy, method, args) -> {
                if (method.getName().equals("getAddressSpace") && args.length == 1) {
                    if ((byId && args[0] instanceof Integer id && id == actual.getSpaceID()) ||
                            (args[0] instanceof String name && name.equals(actual.getName()))) {
                        return replacement;
                    }
                }
                return invoke(real, method, args);
            });
    }

    private static void precedence(Fixture fixture, PcodeOp store) throws Exception {
        Program real = fixture.program();
        Instruction first = fixture.instructions().get(0);
        Varnode input = new Varnode(real.getRegister("a0").getAddress(), 8);
        var constant = real.getAddressFactory().getConstantSpace();
        var opaque = operation(store, PcodeOp.CALLOTHER,
            new Varnode[] { new Varnode(constant.getAddress(0), 4) }, null);
        var unimplemented = operation(store, PcodeOp.UNIMPLEMENTED, new Varnode[0], null);
        for (PcodeOp bad : List.of(opaque, unimplemented)) {
            Instruction instruction = decorate(Instruction.class, first,
                Map.of("getPcode", new PcodeOp[] { store, bad }));
            Storage rejected = stable(fixture, withInstructions(real, List.of(instruction)));
            unknown(rejected);
            require(GhidraVariableStorage.parameterPrefix(real, fixture.function(),
                fixture.function().getParameter(0), TargetRegisterMap.forTarget(fixture.target()),
                rejected, TaskMonitor.DUMMY).isEmpty(), "opaque effects acquired a prefix");
        }
        var write = operation(store, PcodeOp.COPY,
            new Varnode[] { new Varnode(constant.getAddress(7), 8) }, input);
        Instruction explicitWrite = decorate(Instruction.class, first,
            Map.of("getPcode", new PcodeOp[] { store, opaque, write }));
        reason(stable(fixture, withInstructions(real, List.of(explicitWrite))),
            OmissionReason.REGISTER_MODIFIED);
        Instruction call = decorate(Instruction.class, first,
            Map.of("getFlowType", RefType.UNCONDITIONAL_CALL));
        reason(stable(fixture, withInstructions(real, List.of(call))), OmissionReason.CALL_CLOBBERED);
        Instruction badStore = decorate(Instruction.class, first,
            Map.of("getPcode", new PcodeOp[] { offsetWidth(store, 9) }));
        unknown(stable(fixture, withInstructions(real, List.of(badStore))));
        // STORE's selector must remain an independent clobber guard even if
        // the tracked register lives in a RAM space rather than register space.
        var ram = real.getAddressFactory().getDefaultAddressSpace();
        var mapped = new Register("a0", "controlled memory-mapped register", ram.getAddress(0x3000),
            8, real.getLanguage().isBigEndian(), 0);
        require(!GhidraVariableStorage.unprovenStore(real, store) &&
            GhidraVariableStorage.writesRegister(first, mapped),
            "truncated memory proof hid a store into the tracked register's space");
    }

    private static PcodeOp selector(PcodeOp store, AddressFactory factory, long id) {
        return operation(store, PcodeOp.STORE, new Varnode[] {
            new Varnode(factory.getConstantSpace().getAddress(id), 8),
            store.getInput(1), store.getInput(2) }, null);
    }

    private static PcodeOp offsetWidth(PcodeOp store, int bytes) {
        return operation(store, PcodeOp.STORE, new Varnode[] { store.getInput(0),
            new Varnode(store.getInput(1).getAddress(), bytes), store.getInput(2) }, null);
    }

    private static PcodeOp operation(PcodeOp original, int opcode, Varnode[] inputs, Varnode output) {
        return new PcodeOp(original.getSeqnum(), opcode, inputs, output);
    }

    private static PcodeOp store(Fixture fixture) {
        var stores = new ArrayList<PcodeOp>();
        for (PcodeOp operation : fixture.instructions().get(0).getPcode()) {
            if (operation.getOpcode() == PcodeOp.STORE) {
                stores.add(operation);
            }
        }
        require(stores.size() == 1, "first instruction must contain one real STORE");
        return stores.get(0);
    }

    private static Storage stable(Fixture fixture, Program program) throws Exception {
        return GhidraVariableStorage.stableParameter(program, fixture.function(),
            fixture.function().getParameter(0), TargetRegisterMap.forTarget(fixture.target()),
            TaskMonitor.DUMMY);
    }

    private static <T> T decorate(Class<T> api, T original, Map<String, Object> changes) {
        return api.cast(Proxy.newProxyInstance(api.getClassLoader(), new Class<?>[] { api },
            (proxy, method, args) -> changes.containsKey(method.getName())
                ? changes.get(method.getName()) : invoke(original, method, args)));
    }

    private static Object invoke(Object original, java.lang.reflect.Method method, Object[] args)
            throws Throwable {
        try {
            return method.invoke(original, args);
        }
        catch (InvocationTargetException failure) {
            throw failure.getCause();
        }
    }

    private static Program withInstructions(Program original, List<Instruction> instructions) {
        Listing listing = (Listing) Proxy.newProxyInstance(Listing.class.getClassLoader(),
            new Class<?>[] { Listing.class }, (proxy, method, args) -> {
                if (!method.getName().equals("getInstructions")) {
                    throw new AssertionError("unexpected listing API " + method);
                }
                Iterator<Instruction> iterator = instructions.iterator();
                return new InstructionIterator() {
                    public boolean hasNext() { return iterator.hasNext(); }
                    public Instruction next() { return iterator.next(); }
                    public Iterator<Instruction> iterator() { return this; }
                };
            });
        return decorate(Program.class, original, Map.of("getListing", listing));
    }

    private static Fixture fixture(boolean big, boolean truncated) throws Exception {
        String id = "MIPS:" + (big ? "BE" : "LE") + (truncated ? ":64:64-32addr" : ":32:default");
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(id));
        var compiler = truncated ? language.getCompilerSpecByID(new CompilerSpecID("n32"))
            : language.getDefaultCompilerSpec();
        Object owner = new Object();
        var program = new ProgramDB("truncated-store", language, compiler, owner);
        boolean complete = false;
        try {
            int transaction = program.startTransaction("decode real STORE");
            try {
                // sd/sw s8,24(sp); nop; jr ra; nop. sd bytes are from the pinned
                // compiler's actual N32 prologue; no custom p-code in this positive.
                byte[] code = HexFormat.of().parseHex((truncated ? "ffbe0018" : "afbe0018") +
                    "0000000003e0000800000000");
                if (!big) {
                    for (int i = 0; i < code.length; i += 4) {
                        byte first = code[i]; code[i] = code[i + 3]; code[i + 3] = first;
                        byte second = code[i + 1]; code[i + 1] = code[i + 2]; code[i + 2] = second;
                    }
                }
                var start = language.getDefaultSpace().getAddress(0x1000);
                var body = new AddressSet(start, start.add(code.length - 1));
                var block = program.getMemory().createInitializedBlock("code", start,
                    code.length, (byte) 0, TaskMonitor.DUMMY, false);
                block.setExecute(true);
                program.getMemory().setBytes(start, code);
                require(new DisassembleCommand(start, body, true).applyTo(program, TaskMonitor.DUMMY),
                    "real instruction disassembly failed");
                Function function = program.getFunctionManager().createFunction("store", start,
                    body, SourceType.USER_DEFINED);
                function.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
                function.updateFunction(compiler.getDefaultCallingConvention().getName(), function.getReturn(),
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED,
                    new ParameterImpl("value", truncated ? UnsignedLongLongDataType.dataType : IntegerDataType.dataType,
                        program, SourceType.USER_DEFINED));
                var instructions = new ArrayList<Instruction>();
                program.getListing().getInstructions(body, true).forEach(instructions::add);
                require(instructions.size() == 4 && instructions.get(0).getMnemonicString().equals(truncated ? "sd" : "sw"),
                    "fixture was not decoded completely");
                complete = true;
                return new Fixture(program, function, List.copyOf(instructions), owner, big ? "mips" : "mipsel");
            }
            finally {
                program.endTransaction(transaction, complete);
            }
        }
        finally {
            if (!complete) {
                program.release(owner);
            }
        }
    }

    private record Fixture(ProgramDB program, Function function, List<Instruction> instructions,
            Object owner, String target) implements AutoCloseable {
        public void close() { program.release(owner); }
    }

    private static void reject(Program program, PcodeOp store, String label) {
        require(GhidraVariableStorage.unprovenStore(program, store), label + " was accepted");
    }

    private static void unknown(Storage storage) {
        reason(storage, OmissionReason.UNKNOWN_LIFETIME);
        require(((UnavailableStorage) storage).diagnostic().contains("opaque instruction effects"),
            "unknown lifetime diagnostic changed");
    }

    private static void reason(Storage storage, OmissionReason expected) {
        require(storage instanceof UnavailableStorage unavailable && unavailable.reason() == expected,
            "expected " + expected + " but got " + storage);
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
