package ghidradwarfforge;

import java.io.File;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.Iterator;
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
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.OmissionReason;
import ghidradwarfforge.locations.VariableStorageModel.Storage;
import ghidradwarfforge.locations.VariableStorageModel.UnavailableStorage;

/** Real decoded bodies and listing deletion; no inferred instruction bytes. */
public final class RegisterBodyCoverageSmoke {
    private static int checks;

    private record Profile(String language, String code, String target, String first, String second) { }

    private RegisterBodyCoverageSmoke() { }

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (var profile : List.of(
                new Profile("x86:LE:64:default", "9090c3", "x86_64", "EDI", "ESI"),
                new Profile("AARCH64:LE:64:v8A", "1f2003d51f2003d5c0035fd6", "aarch64", "w0", "w1"),
                new Profile("ARM:LE:32:v8", "0220a0e10220a0e11eff2fe1", "arm", "r0", "r1"),
                new Profile("MIPS:BE:32:default", "000000000000000003e0000800000000", "mips", "a0", "a1"),
                new Profile("MIPS:LE:32:default", "00000000000000000800e00300000000", "mips", "a0", "a1"))) {
            try (var fixture = fixture(profile)) {
                checkAll(fixture, fixture.program(), true);
                var instructions = fixture.instructions();
                for (String api : List.of("isLengthOverridden", "getParsedLength")) {
                    var changed = new ArrayList<>(instructions);
                    Instruction original = changed.get(0);
                    Object value = api.equals("isLengthOverridden") ? Boolean.TRUE : original.getLength() + 1;
                    changed.set(0, (Instruction) Proxy.newProxyInstance(Instruction.class.getClassLoader(),
                        new Class<?>[] { Instruction.class }, (proxy, method, arguments) ->
                            method.getName().equals(api) ? value : method.invoke(original, arguments)));
                    checkAll(fixture, withInstructions(fixture.program(), changed), false);
                }
                // Body bytes are covered, but fallthrough executes the excluded
                // gap. This is a flow failure, distinct from missing decoding.
                var separated = new AddressSet(fixture.function().getBody());
                var middle = instructions.get(1);
                separated.delete(middle.getAddress(), middle.getMaxAddress());
                int transaction = fixture.program().startTransaction("discontiguous body");
                try { fixture.function().setBody(separated); }
                finally { fixture.program().endTransaction(transaction, true); }
                checkAll(fixture, fixture.program(), false, "control flow");
                if (instructions.get(0).getLength() > 1) {
                    separated.delete(instructions.get(0).getMaxAddress(), instructions.get(0).getMaxAddress());
                    transaction = fixture.program().startTransaction("partial instruction");
                    try { fixture.function().setBody(separated); }
                    finally { fixture.program().endTransaction(transaction, true); }
                    checkAll(fixture, fixture.program(), false);
                }
            }
            for (int remove : new int[] { 0, 1, -1, -2 }) {
                try (var fixture = fixture(profile)) {
                    var body = new AddressSet(fixture.function().getBody());
                    var instruction = fixture.instructions().get(remove < 0
                        ? fixture.instructions().size() - 1 : remove);
                    var start = remove == -2 ? body.getMinAddress() : instruction.getAddress();
                    var end = remove == -2 ? body.getMaxAddress() : instruction.getMaxAddress();
                    byte[] before = new byte[Math.toIntExact(body.getNumAddresses())];
                    fixture.program().getMemory().getBytes(body.getMinAddress(), before);
                    int transaction = fixture.program().startTransaction("delete listing only");
                    try {
                        fixture.program().getListing().clearCodeUnits(start, end, false);
                        fixture.function().setBody(body);
                    }
                    finally { fixture.program().endTransaction(transaction, true); }
                    byte[] after = new byte[before.length];
                    fixture.program().getMemory().getBytes(body.getMinAddress(), after);
                    require(java.util.Arrays.equals(before, after), "listing deletion changed code bytes");
                    checkAll(fixture, fixture.program(), false);
                    if (remove == -2) {
                        var cancelled = new TaskMonitorAdapter(true);
                        cancelled.cancel();
                        try {
                            GhidraVariableStorage.stableParameter(fixture.program(), fixture.function(),
                                parameter(fixture), TargetRegisterMap.forTarget(profile.target()), cancelled);
                            throw new AssertionError("empty listing swallowed cancellation");
                        }
                        catch (CancelledException expected) { checks++; }
                    }
                }
            }
            System.out.println("register-body-coverage-profile=" + profile.language() + " PASS");
        }
        System.out.println("register-body-coverage-smoke=PASS checks=" + checks);
    }

    private static ParameterImpl parameter(Fixture fixture) throws Exception {
        return new ParameterImpl("value", IntegerDataType.dataType,
            fixture.program().getRegister(fixture.profile().first()), fixture.program());
    }

    private static void checkAll(Fixture fixture, Program program, boolean available) throws Exception {
        checkAll(fixture, program, available, "incomplete instruction coverage");
    }

    private static void checkAll(Fixture fixture, Program program, boolean available, String diagnostic) throws Exception {
        var real = fixture.program();
        var map = TargetRegisterMap.forTarget(fixture.profile().target());
        var first = real.getRegister(fixture.profile().first());
        var second = real.getRegister(fixture.profile().second());
        var pair = new VariableStorage(real, first, second);
        var scalar = parameter(fixture);
        var storage = GhidraVariableStorage.stableParameter(program, fixture.function(), scalar, map, TaskMonitor.DUMMY);
        check(storage, available, diagnostic);
        var sliceType = new ghidra.program.model.data.ArrayDataType(
            ghidra.program.model.data.UnsignedCharDataType.dataType, 3, 1);
        var slice = new VariableStorage(real, new ghidra.program.model.pcode.Varnode(first.getAddress(), 3));
        check(GhidraVariableStorage.stableParameter(program, fixture.function(),
            new ParameterImpl("slice", sliceType, slice, real), map, TaskMonitor.DUMMY), available, diagnostic);
        if (!available) {
            require(GhidraVariableStorage.parameterPrefix(program, fixture.function(), scalar,
                map, storage, TaskMonitor.DUMMY).isEmpty(), "incomplete listing invented a prefix");
        }
        check(GhidraVariableStorage.stableLocal(program, fixture.function(),
            new LocalVariableImpl("local", 0, IntegerDataType.dataType, first, real), map, TaskMonitor.DUMMY), available, diagnostic);
        check(GhidraVariableStorage.stableParameter(program, fixture.function(),
            new ParameterImpl("pair", LongLongDataType.dataType, pair, real), map, TaskMonitor.DUMMY), available, diagnostic);
        check(GhidraVariableStorage.stableLocal(program, fixture.function(),
            new LocalVariableImpl("pair_local", 0, LongLongDataType.dataType, pair, real), map, TaskMonitor.DUMMY), available, diagnostic);
    }

    private static void check(Storage storage, boolean available, String diagnostic) {
        require(storage.available() == available, "unexpected storage " + storage);
        if (!available) {
            require(storage instanceof UnavailableStorage unavailable &&
                unavailable.reason() == OmissionReason.UNKNOWN_LIFETIME &&
                unavailable.diagnostic().contains(diagnostic),
                "wrong coverage diagnostic " + storage);
        }
    }

    private static Program withInstructions(Program real, List<Instruction> instructions) {
        Listing listing = (Listing) Proxy.newProxyInstance(Listing.class.getClassLoader(),
            new Class<?>[] { Listing.class }, (proxy, method, arguments) -> {
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
        return (Program) Proxy.newProxyInstance(Program.class.getClassLoader(), new Class<?>[] { Program.class },
            (proxy, method, arguments) -> method.getName().equals("getListing") ? listing : method.invoke(real, arguments));
    }

    private static Fixture fixture(Profile profile) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(profile.language()));
        var owner = new Object();
        var program = new ProgramDB("register-body", language, language.getDefaultCompilerSpec(), owner);
        boolean complete = false;
        try {
            int transaction = program.startTransaction("decode body");
            try {
                byte[] bytes = HexFormat.of().parseHex(profile.code());
                var start = language.getDefaultSpace().getAddress(0x1000);
                var body = new AddressSet(start, start.add(bytes.length - 1));
                var block = program.getMemory().createInitializedBlock("code", start, bytes.length,
                    (byte) 0, TaskMonitor.DUMMY, false);
                block.setExecute(true);
                program.getMemory().setBytes(start, bytes);
                if (profile.language().startsWith("ARM:")) {
                    program.getProgramContext().setValue(program.getRegister("TMode"), start,
                        body.getMaxAddress(), BigInteger.ZERO);
                }
                require(new DisassembleCommand(start, body, true).applyTo(program, TaskMonitor.DUMMY), "decode failed");
                var function = program.getFunctionManager().createFunction("fixture", start, body, SourceType.USER_DEFINED);
                var instructions = new ArrayList<Instruction>();
                program.getListing().getInstructions(body, true).forEach(instructions::add);
                require(instructions.size() >= 3, "fixture did not decode");
                complete = true;
                return new Fixture(profile, program, function, List.copyOf(instructions), owner);
            }
            finally { program.endTransaction(transaction, complete); }
        }
        finally { if (!complete) { program.release(owner); } }
    }

    private record Fixture(Profile profile, ProgramDB program, Function function,
            List<Instruction> instructions, Object owner) implements AutoCloseable {
        public void close() { program.release(owner); }
    }

    private static void require(boolean value, String message) {
        checks++;
        if (!value) { throw new AssertionError(message); }
    }
}
