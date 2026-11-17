package ghidradwarfforge;

import java.io.File;
import java.lang.reflect.Proxy;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.RefType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.RegisterStorage;
import ghidradwarfforge.locations.VariableStorageModel.RegisterRelativeStorage;

/** Raw memory-proof contracts in real language contexts, not machine-code support claims. */
public final class CallMemoryRawSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        run();
    }

    static void run() throws Exception {
        for (String id : List.of("x86:LE:32:default", "x86:LE:64:default", "AARCH64:LE:64:v8A")) {
            try (var fixture = new Fixture(id)) { fixture.check(); }
        }
        System.out.println("call-memory-raw=PASS checks=" + checks);
    }

    private static final class Fixture implements AutoCloseable {
        final Object owner = new Object();
        final ProgramDB program;
        final List<Instruction> instructions = new ArrayList<>();
        final Address entry;
        final byte[] bytes;
        final Varnode sp, carrier, space, value;
        final int width;

        Fixture(String id) throws Exception {
            var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(id));
            program = new ProgramDB("raw-memory-proof", language, language.getDefaultCompilerSpec(), owner);
            entry = language.getDefaultSpace().getAddress(0x1000);
            bytes = HexFormat.of().parseHex(id.startsWith("x86") ? "9090c3" : "1f2003d51f2003d5c0035fd6");
            int tx = program.startTransaction("memory-proof instruction context");
            try {
                var body = new AddressSet(entry, entry.add(bytes.length - 1));
                program.getMemory().createInitializedBlock("code", entry, bytes.length, (byte) 0,
                    TaskMonitor.DUMMY, false).setExecute(true);
                program.getMemory().setBytes(entry, bytes);
                require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY), "decode context");
                program.getListing().getInstructions(body, true).forEach(instructions::add);
            }
            finally { program.endTransaction(tx, true); }
            require(instructions.size() == 3, "three decoded instructions");
            var pointer = program.getCompilerSpec().getStackPointer();
            width = pointer.getMinimumByteSize();
            sp = new Varnode(pointer.getAddress(), width);
            var register = program.getRegister(id.startsWith("x86") ? (width == 8 ? "RAX" : "EAX") : "x0");
            carrier = new Varnode(register.getAddress(), width);
            space = constant(Integer.toUnsignedLong(language.getDefaultDataSpace().getSpaceID()), 4);
            value = constant(7, 1);
        }

        void check() throws Exception {
            long modification = program.getModificationNumber();
            profiles();
            var oneByte = new CallMemoryEffects.Summary(0, Set.of(new CallMemoryEffects.Range(0, 1)));
            var empty = new CallMemoryEffects.Summary(0, Set.of());
            PcodeOp store = op(PcodeOp.STORE, null, space, sp, value);
            test("valid store", oneByte, new PcodeOp[] {store}, new PcodeOp[0]);
            for (Varnode[] inputs : new Varnode[][] {
                    {}, {space}, {space, sp}, {space, sp, value, value},
                    {null, sp, value}, {carrier, sp, value}, {space, null, value},
                    {space, sp, null}, {space, sp, constant(0, 0)},
                    {constant(space.getOffset() + 1, 4), sp, value},
                    {constant(space.getOffset() | (1L << 40), 8), sp, value},
                    {space, constant(0, width), value}, {space, carrier, value}}) {
                test("invalid store " + Arrays.toString(inputs), null,
                    new PcodeOp[] {op(PcodeOp.STORE, null, inputs)}, new PcodeOp[0]);
            }
            for (int size : new int[] {1, 2, 4, 8, 16}) {
                if (size != width) test("wrong address width " + size, null,
                    new PcodeOp[] {op(PcodeOp.STORE, null, space, new Varnode(sp.getAddress(), size), value)}, new PcodeOp[0]);
            }
            // Both encodings of a signed address-space ID denote the same space.
            test("signed space id", oneByte, new PcodeOp[] {op(PcodeOp.STORE, null,
                constant((int) space.getOffset(), 8), sp, value)}, new PcodeOp[0]);

            PcodeOp useCarrier = op(PcodeOp.STORE, null, space, carrier, value);
            test("copied stack pointer", oneByte, new PcodeOp[] {op(PcodeOp.COPY, carrier, sp), useCarrier}, new PcodeOp[0]);
            for (int opcode : new int[] {PcodeOp.COPY, PcodeOp.INT_ADD, PcodeOp.INT_SUB}) {
                List<Varnode[]> invalid = new ArrayList<>();
                invalid.add(new Varnode[0]);
                invalid.add(new Varnode[] {null});
                invalid.add(new Varnode[] {sp, constant(0, width), value});
                if (opcode == PcodeOp.COPY) invalid.add(new Varnode[] {sp, sp});
                else {
                    invalid.add(new Varnode[] {sp});
                    invalid.add(new Varnode[] {null, constant(0, width)});
                    invalid.add(new Varnode[] {sp, null});
                    invalid.add(new Varnode[] {carrier, constant(0, width)});
                    invalid.add(new Varnode[] {sp, carrier});
                }
                for (int size : new int[] {0, 1, 2, 4, 8, 16}) {
                    if (size == width) continue;
                    var wrong = new Varnode(sp.getAddress(), size);
                    invalid.add(opcode == PcodeOp.COPY ? new Varnode[] {wrong} : new Varnode[] {wrong, constant(0, width)});
                    if (opcode != PcodeOp.COPY) invalid.add(new Varnode[] {sp, constant(0, size)});
                }
                for (Varnode[] inputs : invalid) test("invalid derivation " + opcode + " " + Arrays.toString(inputs), null,
                    new PcodeOp[] {op(opcode, carrier, inputs), useCarrier}, new PcodeOp[0]);
                Varnode[] valid = opcode == PcodeOp.COPY ? new Varnode[] {sp} : new Varnode[] {sp, constant(0, width)};
                test("valid derivation " + opcode, oneByte, new PcodeOp[] {op(opcode, carrier, valid), useCarrier}, new PcodeOp[0]);
            }
            test("memory output", null, new PcodeOp[] {op(PcodeOp.COPY, new Varnode(entry, width), sp)}, new PcodeOp[0]);
            test("constant output does not prove an address", null,
                new PcodeOp[] {op(PcodeOp.COPY, constant(0, width), sp),
                    op(PcodeOp.STORE, null, space, constant(0, width), value)}, new PcodeOp[0]);
            test("unrelated unknown register write", empty,
                new PcodeOp[] {op(PcodeOp.INT_XOR, carrier, carrier, carrier)}, new PcodeOp[0]);
            var temporary = new Varnode(program.getAddressFactory().getUniqueSpace().getAddress(0x100), width);
            test("same-instruction temporary", oneByte, new PcodeOp[] {op(PcodeOp.COPY, temporary, sp),
                op(PcodeOp.STORE, null, space, temporary, value)}, new PcodeOp[0]);
            test("temporary expires at instruction boundary", null, new PcodeOp[] {op(PcodeOp.COPY, temporary, sp)},
                new PcodeOp[] {op(PcodeOp.STORE, null, space, temporary, value)});
            test("partial stack-pointer output", null,
                new PcodeOp[] {op(PcodeOp.COPY, new Varnode(sp.getAddress(), 1), value)}, new PcodeOp[0]);
            test("absolute stack pointer", null, new PcodeOp[] {op(PcodeOp.COPY, sp, constant(0, width))}, new PcodeOp[0]);
            byte[] after = new byte[bytes.length];
            program.getMemory().getBytes(entry, after);
            require(Arrays.equals(bytes, after) && modification == program.getModificationNumber(), "proof preserves saved program");
        }

        Varnode constant(long number, int size) {
            return new Varnode(program.getAddressFactory().getConstantSpace().getAddress(number), size);
        }

        PcodeOp op(int opcode, Varnode output, Varnode... inputs) {
            return new PcodeOp(entry, 0, opcode, inputs, output);
        }

        void test(String label, CallMemoryEffects.Summary expected, PcodeOp[] first, PcodeOp[] second) throws Exception {
            test(program, label, expected, first, second);
        }

        void test(Program selectedProgram, String label, CallMemoryEffects.Summary expected,
                PcodeOp[] first, PcodeOp[] second) throws Exception {
            List<Instruction> selected = new ArrayList<>();
            for (int i = 0; i < 3; i++) {
                Instruction original = instructions.get(i);
                PcodeOp[] code = i == 0 ? first : i == 1 ? second : new PcodeOp[0];
                Address next = i == 2 ? null : instructions.get(i + 1).getAddress();
                selected.add((Instruction) Proxy.newProxyInstance(Instruction.class.getClassLoader(),
                    new Class<?>[] {Instruction.class}, (proxy, method, arguments) -> switch (method.getName()) {
                        case "getPcode" -> code;
                        case "getResultObjects" -> new Object[0];
                        case "getFlowType" -> next == null ? RefType.TERMINATOR : RefType.FALL_THROUGH;
                        case "getFallThrough" -> next;
                        case "getFlows" -> new Address[0];
                        default -> method.invoke(original, arguments);
                    }));
            }
            try {
                var actual = CallMemoryEffects.summarize(selectedProgram, entry, selected, Map.of(), Map.of(), TaskMonitor.DUMMY);
                require(Objects.equals(expected, actual), label + " expected=" + expected + " actual=" + actual);
            }
            catch (RuntimeException failure) { throw new AssertionError(label + " must refuse without crashing", failure); }
        }

        void profiles() throws Exception {
            var empty = new CallMemoryEffects.Summary(0, Set.of());
            for (String defect : List.of("transparent", "missing-stack-pointer", "partial-stack-pointer", "missing-memory",
                    "overlay", "register-space", "word-addressed", "zero-pointer", "wide-pointer", "pointer-mismatch")) {
                Program selected = profile(defect, true);
                test(selected, "target profile " + defect, defect.equals("transparent") ? empty : null,
                    new PcodeOp[0], new PcodeOp[0]);
                var state = StackValueFlow.forStackLocal(selected, width, 0);
                require((state != null) == defect.equals("transparent"), "stack local accepted invalid target: " + defect);
                require((StackValueFlow.forIncomingPiece(selected, carrier) != null) == defect.equals("transparent"),
                    "incoming value accepted invalid target: " + defect);
                if (state != null) initializedLocation(state, selected);
                test("target profile retry", empty, new PcodeOp[0], new PcodeOp[0]);
            }
            require(StackValueFlow.forStackLocal(profile("unregistered-memory", true), width, 0) == null,
                "stack proof used an unregistered memory-space identity");
            for (int invalid : new int[] { 0, -1 }) {
                require(StackValueFlow.forStackLocal(program, invalid, 0) == null, "nonpositive local width acquired a state");
            }
            for (Varnode invalid : List.of(sp, new Varnode(carrier.getAddress(), 0),
                    new Varnode(carrier.getAddress(), width * 2), new Varnode(entry, width), constant(7, width),
                    new Varnode(program.getAddressFactory().getUniqueSpace().getAddress(0x100), width))) {
                require(StackValueFlow.forIncomingPiece(program, invalid) == null,
                    "non-value carrier acquired an incoming fact: " + invalid);
            }
            var map = registerMap();
            var incoming = StackValueFlow.forIncomingPiece(program, carrier);
            require(incoming != null && incoming.location(map) instanceof RegisterStorage register &&
                register.register().dwarfNumber() == 0 && register.bitSize() == width * 8,
                "valid incoming register did not retain its exact location");
            var slot = new Varnode(program.getAddressFactory().getStackSpace().getAddress(16), width);
            var stack = StackValueFlow.forIncomingPiece(program, slot);
            require(stack != null && stack.location(map) instanceof RegisterRelativeStorage relative &&
                relative.register().dwarfNumber() == stackNumber() && relative.byteOffset() == 16,
                "valid incoming stack piece did not retain its exact coordinate");
            initializedLocation(StackValueFlow.forStackLocal(program, width, 0), program);
            // This is a raw memory-proof contract, not a claim of an upward-stack ABI.
            // An increase releases [old,new) on a downward stack; a decrease releases
            // [new,old) on an upward stack. Allocation must not count as a write/release.
            long minimum = width == 8 ? Long.MIN_VALUE : Integer.MIN_VALUE;
            long maximum = width == 8 ? Long.MAX_VALUE : Integer.MAX_VALUE;
            for (boolean negative : new boolean[] { true, false }) {
                for (long delta : new long[] { minimum, -width, -1, 0, 1, width, maximum }) {
                    boolean releases = negative ? delta > 0 : delta < 0;
                    var ranges = releases ? Set.of(new CallMemoryEffects.Range(Math.min(0, delta), Math.max(0, delta)))
                        : Set.<CallMemoryEffects.Range>of();
                    var expected = new CallMemoryEffects.Summary(delta, ranges);
                    test(profile("transparent", negative), "stack direction=" + negative + " delta=" + delta,
                        expected, new PcodeOp[] { op(PcodeOp.INT_ADD, sp, sp, constant(delta, width)) }, new PcodeOp[0]);
                }
            }
        }

        TargetRegisterMap registerMap() {
            return TargetRegisterMap.forTarget(program.getLanguageID().toString().startsWith("x86") ?
                (width == 8 ? "x86_64" : "x86") : "aarch64");
        }

        int stackNumber() {
            return program.getLanguageID().toString().startsWith("x86") ? (width == 8 ? 7 : 4) : 31;
        }

        void initializedLocation(StackValueFlow state, Program selected) throws Exception {
            require(state != null && !state.location(registerMap()).available(), "local acquired a value before its definition");
            PcodeOp[] operations = { op(PcodeOp.STORE, null, space, sp, constant(7, width)) };
            var instruction = (Instruction) Proxy.newProxyInstance(Instruction.class.getClassLoader(),
                new Class<?>[] { Instruction.class }, (proxy, method, args) -> {
                    if (method.getName().equals("getPcode")) return operations;
                    if (method.getName().equals("getResultObjects")) return new Object[0];
                    if (method.getName().equals("getProgram")) return selected;
                    try { return method.invoke(instructions.getFirst(), args); }
                    catch (InvocationTargetException failure) { throw failure.getCause(); }
                });
            require(state.advance(instruction, true, TaskMonitor.DUMMY), "exact defining STORE was not admitted");
            require(state.location(registerMap()) instanceof RegisterRelativeStorage relative &&
                relative.register().dwarfNumber() == stackNumber() && relative.byteOffset() == 0,
                "completed STORE did not establish the exact stack location");
        }

        Program profile(String defect, boolean growsNegative) {
            var originalSpace = program.getLanguage().getDefaultDataSpace();
            var selectedSpace = (AddressSpace) Proxy.newProxyInstance(AddressSpace.class.getClassLoader(),
                new Class<?>[] { AddressSpace.class }, (proxy, method, args) -> {
                    String name = method.getName();
                    if (name.equals("isOverlaySpace") && defect.equals("overlay")) return true;
                    if (name.equals("getType") && defect.equals("register-space")) return AddressSpace.TYPE_REGISTER;
                    if (name.equals("getAddressableUnitSize") && defect.equals("word-addressed")) return 2;
                    if (name.equals("getPointerSize")) {
                        if (defect.equals("zero-pointer")) return 0;
                        if (defect.equals("wide-pointer")) return 9;
                        if (defect.equals("pointer-mismatch")) return width - 1;
                    }
                    try { return method.invoke(originalSpace, args); }
                    catch (InvocationTargetException failure) { throw failure.getCause(); }
                });
            var language = (Language) Proxy.newProxyInstance(Language.class.getClassLoader(), new Class<?>[] { Language.class },
                (proxy, method, args) -> {
                    if (method.getName().equals("getDefaultDataSpace")) return defect.equals("missing-memory") ? null : selectedSpace;
                    try { return method.invoke(program.getLanguage(), args); }
                    catch (InvocationTargetException failure) { throw failure.getCause(); }
                });
            var factory = (AddressFactory) Proxy.newProxyInstance(AddressFactory.class.getClassLoader(),
                new Class<?>[] { AddressFactory.class }, (proxy, method, args) -> {
                    if (!defect.equals("unregistered-memory") && method.getName().equals("getAddressSpace") &&
                            args[0] instanceof Integer id && id == originalSpace.getSpaceID()) return selectedSpace;
                    try { return method.invoke(program.getAddressFactory(), args); }
                    catch (InvocationTargetException failure) { throw failure.getCause(); }
                });
            var compiler = (CompilerSpec) Proxy.newProxyInstance(CompilerSpec.class.getClassLoader(),
                new Class<?>[] { CompilerSpec.class }, (proxy, method, args) -> {
                    if (method.getName().equals("getStackPointer")) {
                        if (defect.equals("missing-stack-pointer")) return null;
                        if (defect.equals("partial-stack-pointer")) {
                            var alias = program.getRegister(program.getLanguageID().toString().startsWith("x86") ?
                                (width == 8 ? "ESP" : "SP") : "wsp");
                            require(alias != null && alias != alias.getBaseRegister(), "partial pointer fixture lacks an alias");
                            return alias;
                        }
                    }
                    if (method.getName().equals("stackGrowsNegative")) return growsNegative;
                    try { return method.invoke(program.getCompilerSpec(), args); }
                    catch (InvocationTargetException failure) { throw failure.getCause(); }
                });
            return (Program) Proxy.newProxyInstance(Program.class.getClassLoader(), new Class<?>[] { Program.class },
                (proxy, method, args) -> {
                    if (method.getName().equals("getLanguage")) return language;
                    if (method.getName().equals("getCompilerSpec")) return compiler;
                    if (method.getName().equals("getAddressFactory")) return factory;
                    try { return method.invoke(program, args); }
                    catch (InvocationTargetException failure) { throw failure.getCause(); }
                });
        }

        @Override public void close() { program.flushEvents(); program.release(owner); }
    }

    private static void require(boolean condition, String label) {
        checks++;
        if (!condition) throw new AssertionError(label);
    }
}
