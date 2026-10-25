package ghidradwarfforge;

import java.io.File;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.List;

import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.LocalVariableImpl;
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
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.OmissionReason;
import ghidradwarfforge.locations.VariableStorageModel.Storage;
import ghidradwarfforge.locations.VariableStorageModel.UnavailableStorage;

/** Real instruction decoding plus controlled metadata negatives; no native producer. */
public final class OpaqueRegisterEffectsSmoke {
    private OpaqueRegisterEffectsSmoke() {
    }

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        try (var syscall = fixture("AARCH64:LE:64:v8A", "010000d41f2003d5c0035fd6")) {
            checkSyscall(syscall);
        }
        try (var ordinary = fixture("AARCH64:LE:64:v8A", "1f2003d5c0035fd6")) {
            require(stable(ordinary, ordinary.program(), "w0", "aarch64").available(),
                "ordinary modeled code lost its stable register");
        }
        try (var arm = fixture("ARM:LE:32:v8", "1eff2fe1")) {
            checkTerminal(arm);
        }
        try (var arm = fixture("ARM:LE:32:v8", "0000a0e300f020e31eff2fe1")) {
            checkTerminalPrefix(arm);
        }
        System.out.println("opaque-register-effects-smoke=PASS");
    }

    private static void checkSyscall(Fixture fixture) throws Exception {
        ProgramDB real = fixture.program();
        var map = TargetRegisterMap.forTarget("aarch64");
        var incoming = real.getRegister("w0");
        Parameter parameter = new ParameterImpl("value", IntegerDataType.dataType, incoming, real);
        var local = new LocalVariableImpl("copy", 0, IntegerDataType.dataType, incoming, real);
        var pairStorage = new VariableStorage(real, incoming, real.getRegister("w1"));
        Parameter pair = new ParameterImpl("pair", LongLongDataType.dataType, pairStorage, real);
        var pairLocal = new LocalVariableImpl("pair_copy", 0, LongLongDataType.dataType,
            pairStorage, real);
        Instruction syscall = fixture.instructions().get(0);
        require(syscall.getFlowType().isFallthrough() && syscall.getResultObjects().length == 0 &&
            syscall.getPcode().length == 1 &&
            syscall.getPcode()[0].getOpcode() == PcodeOp.CALLOTHER &&
            syscall.getPcode()[0].getOutput() == null,
            "pinned AArch64 SVC no longer exercises hidden register effects");
        Storage rejected = GhidraVariableStorage.stableParameter(real, fixture.function(),
            parameter, map, TaskMonitor.DUMMY);
        unknown(rejected);
        unknown(GhidraVariableStorage.stableLocal(real, fixture.function(), local, map,
            TaskMonitor.DUMMY));
        unknown(GhidraVariableStorage.stableParameter(real, fixture.function(), pair, map,
            TaskMonitor.DUMMY));
        unknown(GhidraVariableStorage.stableLocal(real, fixture.function(), pairLocal, map,
            TaskMonitor.DUMMY));
        require(GhidraVariableStorage.parameterPrefix(real, fixture.function(), parameter,
            map, rejected, TaskMonitor.DUMMY).isEmpty(), "opaque effects invented a prefix");

        // An explicit unrelated output does not describe all userop side effects.
        var userop = syscall.getPcode()[0];
        PcodeOp withOutput = operation(syscall, PcodeOp.CALLOTHER, userop.getInputs(),
            new Varnode(real.getRegister("x2").getAddress(), 8));
        unknown(stable(fixture, withInstructions(real, replaceFirst(fixture,
            decorate(syscall, "getPcode", new PcodeOp[] { withOutput }))), "w0", "aarch64"));
        PcodeOp missing = operation(syscall, PcodeOp.UNIMPLEMENTED, new Varnode[0], null);
        unknown(stable(fixture, withInstructions(real, replaceFirst(fixture,
            decorate(syscall, "getPcode", new PcodeOp[] { missing }))), "w0", "aarch64"));

        // A later modeled cause keeps its existing, more precise diagnostic.
        var middle = fixture.instructions().get(1);
        var call = decorate(middle, "getFlowType", RefType.UNCONDITIONAL_CALL);
        reason(stable(fixture, withInstructions(real,
            List.of(syscall, call, fixture.instructions().get(2))), "w0", "aarch64"),
            OmissionReason.CALL_CLOBBERED);
        PcodeOp write = operation(middle, PcodeOp.COPY,
            new Varnode[] { new Varnode(real.getAddressFactory().getConstantSpace()
                .getAddress(7), 4) }, new Varnode(incoming.getAddress(), 4));
        reason(stable(fixture, withInstructions(real, List.of(syscall,
            decorate(middle, "getPcode", new PcodeOp[] { write }),
            fixture.instructions().get(2))), "w0", "aarch64"), OmissionReason.REGISTER_MODIFIED);

        var cancelled = new TaskMonitorAdapter(true);
        cancelled.cancel();
        try {
            GhidraVariableStorage.stableParameter(real, fixture.function(), parameter, map, cancelled);
            throw new AssertionError("cancelled opaque scan completed");
        }
        catch (CancelledException expected) {
            // Cancellation remains visible to the exporter.
        }
    }

    private static void checkTerminal(Fixture fixture) throws Exception {
        ProgramDB real = fixture.program();
        Instruction terminal = fixture.instructions().get(0);
        PcodeOp[] pcode = terminal.getPcode();
        require(terminal.getFlowType().isTerminal() && terminal.getFallThrough() == null &&
            pcode[pcode.length - 1].getOpcode() == PcodeOp.RETURN &&
            Arrays.stream(pcode).anyMatch(op -> op.getOpcode() == PcodeOp.CALLOTHER &&
                "setISAMode".equals(real.getLanguage().getUserDefinedOpName(
                    Math.toIntExact(op.getInput(0).getOffset())))),
            "pinned ARM BX LR no longer exercises its opaque return operation");
        require(stable(fixture, real, "r0", "arm").available(),
            "pre-return integer value lost its valid location");
        for (String name : List.of("s0", "s1")) {
            Parameter floating = new ParameterImpl("floating", FloatDataType.dataType,
                real.getRegister(name), real);
            require(GhidraVariableStorage.stableParameter(real, fixture.function(), floating,
                TargetRegisterMap.forTarget("arm"), TaskMonitor.DUMMY).available(),
                "pre-return scalar floating slice lost its valid location: " + name);
        }
        var invalidMetadata = List.of(
            decorate(terminal, "getFlowOverride", FlowOverride.RETURN),
            decorate(terminal, "isInDelaySlot", true),
            decorate(terminal, "getDelaySlotDepth", 1),
            decorate(terminal, "getFlowType", RefType.FALL_THROUGH),
            decorate(terminal, "getFlowType", RefType.CONDITIONAL_TERMINATOR),
            decorate(terminal, "getFlowType", RefType.JUMP_TERMINATOR),
            decorate(terminal, "getFallThrough", terminal.getMaxAddress().next()));
        for (Instruction invalid : invalidMetadata) {
            unknown(stable(fixture, withInstructions(real, List.of(invalid)), "r0", "arm"));
        }
        PcodeOp userop = Arrays.stream(pcode).filter(op -> op.getOpcode() == PcodeOp.CALLOTHER)
            .findFirst().orElseThrow();
        PcodeOp returns = pcode[pcode.length - 1];
        var unrelated = new Varnode(real.getRegister("r1").getAddress(), 4);
        var invalidPcode = List.of(
            new PcodeOp[] { userop },
            new PcodeOp[] { userop, returns, operation(terminal, PcodeOp.COPY,
                new Varnode[] { unrelated }, unrelated) },
            new PcodeOp[] { userop, operation(terminal, PcodeOp.RETURN, new Varnode[0], null) },
            new PcodeOp[] { userop, operation(terminal, PcodeOp.RETURN,
                new Varnode[] { null }, null) },
            new PcodeOp[] { userop, operation(terminal, PcodeOp.RETURN,
                new Varnode[] { new Varnode(unrelated.getAddress(), 1) }, null) },
            new PcodeOp[] { userop, operation(terminal, PcodeOp.RETURN,
                new Varnode[] { unrelated, unrelated }, null) },
            new PcodeOp[] { userop, operation(terminal, PcodeOp.RETURN,
                returns.getInputs(), unrelated) },
            new PcodeOp[] { operation(terminal, PcodeOp.CALLOTHER, new Varnode[0], null), returns },
            new PcodeOp[] { operation(terminal, PcodeOp.CALLOTHER,
                new Varnode[] { unrelated }, null), returns },
            new PcodeOp[] { operation(terminal, PcodeOp.UNIMPLEMENTED, new Varnode[0], null), returns });
        for (PcodeOp[] invalid : invalidPcode) {
            unknown(stable(fixture, withInstructions(real, List.of(
                decorate(terminal, "getPcode", invalid))), "r0", "arm"));
        }
        for (int control : new int[] { PcodeOp.BRANCH, PcodeOp.CBRANCH, PcodeOp.BRANCHIND,
                PcodeOp.CALL, PcodeOp.CALLIND, PcodeOp.RETURN }) {
            PcodeOp[] invalid = { userop, operation(terminal, control, returns.getInputs(), null),
                returns };
            unknown(stable(fixture, withInstructions(real, List.of(
                decorate(terminal, "getPcode", invalid))), "r0", "arm"));
        }
        // A real modeled write remains disqualifying even on this return boundary.
        var incoming = new Varnode(real.getRegister("r0").getAddress(), 4);
        PcodeOp[] clobber = { userop, operation(terminal, PcodeOp.COPY,
            new Varnode[] { unrelated }, incoming), returns };
        reason(stable(fixture, withInstructions(real, List.of(
            decorate(terminal, "getPcode", clobber))), "r0", "arm"),
            OmissionReason.REGISTER_MODIFIED);
    }

    private static Storage stable(Fixture fixture, Program program, String name, String target)
            throws Exception {
        Parameter parameter = new ParameterImpl("value", IntegerDataType.dataType,
            fixture.program().getRegister(name), fixture.program());
        return GhidraVariableStorage.stableParameter(program, fixture.function(), parameter,
            TargetRegisterMap.forTarget(target), TaskMonitor.DUMMY);
    }

    private static void checkTerminalPrefix(Fixture fixture) throws Exception {
        var real = fixture.program();
        var terminal = fixture.instructions().getLast();
        require(fixture.instructions().size() == 3 &&
            fixture.instructions().getFirst().toString().startsWith("mov r0,"),
            "expected decoded ARM incoming register overwrite");
        prefix(fixture, real, true);
        var userop = Arrays.stream(terminal.getPcode())
            .filter(op -> op.getOpcode() == PcodeOp.CALLOTHER).findFirst().orElseThrow();
        var returns = terminal.getPcode()[terminal.getPcode().length - 1];
        var register = new Varnode(real.getRegister("r1").getAddress(), 4);
        var invalid = new ArrayList<Instruction>(List.of(
            decorate(terminal, "getFlowOverride", FlowOverride.RETURN),
            decorate(terminal, "isInDelaySlot", true),
            decorate(terminal, "getDelaySlotDepth", 1),
            decorate(terminal, "getFlowType", RefType.CONDITIONAL_TERMINATOR),
            decorate(terminal, "getFlowType", RefType.JUMP_TERMINATOR),
            decorate(terminal, "getFallThrough", terminal.getMaxAddress().next()),
            decorate(terminal, "isLengthOverridden", true),
            decorate(terminal, "isFallThroughOverridden", true),
            decorate(terminal, "getLength", 0),
            decorate(terminal, "getParsedLength", 2),
            decorate(terminal, "getMaxAddress", terminal.getMaxAddress().previous())));
        for (PcodeOp[] operations : List.of(
                new PcodeOp[] { userop },
                new PcodeOp[] { returns, userop },
                new PcodeOp[] { userop, operation(terminal, PcodeOp.RETURN, new Varnode[0], null) },
                new PcodeOp[] { operation(terminal, PcodeOp.CALLOTHER, new Varnode[0], null), returns },
                new PcodeOp[] { operation(terminal, PcodeOp.CALLOTHER,
                    new Varnode[] { register }, null), returns },
                new PcodeOp[] { userop, operation(terminal, PcodeOp.UNIMPLEMENTED,
                    new Varnode[0], null), returns })) {
            invalid.add(decorate(terminal, "getPcode", operations));
        }
        for (int control : new int[] { PcodeOp.BRANCH, PcodeOp.CBRANCH, PcodeOp.BRANCHIND,
                PcodeOp.CALL, PcodeOp.CALLIND, PcodeOp.RETURN }) {
            invalid.add(decorate(terminal, "getPcode", new PcodeOp[] {
                userop, operation(terminal, control, returns.getInputs(), null), returns }));
        }
        for (Instruction replacement : invalid) {
            var instructions = new ArrayList<>(fixture.instructions());
            instructions.set(2, replacement);
            prefix(fixture, withInstructions(real, instructions), false);
        }
        // A valid userop on an ordinary earlier instruction remains opaque,
        // even after the first overwrite and before an otherwise valid return.
        var middle = fixture.instructions().get(1);
        prefix(fixture, withInstructions(real, List.of(fixture.instructions().getFirst(),
            decorate(middle, "getPcode", new PcodeOp[] { userop }), terminal)), false);
        System.out.println("terminal-return-prefix-model=PASS scalar-and-composite negatives=" +
            (invalid.size() + 1));
    }

    private static void prefix(Fixture fixture, Program program, boolean available) throws Exception {
        var real = fixture.program();
        var map = TargetRegisterMap.forTarget("arm");
        for (Parameter parameter : List.of(
                new ParameterImpl("scalar", IntegerDataType.dataType, real.getRegister("r0"), real),
                new ParameterImpl("pair", LongLongDataType.dataType,
                    new VariableStorage(real, real.getRegister("r0"), real.getRegister("r1")), real))) {
            var rejected = GhidraVariableStorage.stableParameter(program, fixture.function(),
                parameter, map, TaskMonitor.DUMMY);
            reason(rejected, OmissionReason.REGISTER_MODIFIED);
            var intervals = GhidraVariableStorage.parameterPrefix(program, fixture.function(),
                parameter, map, rejected, TaskMonitor.DUMMY);
            if (available) {
                require(intervals.size() == 2 && intervals.get(0).start() == 0x1000 &&
                    intervals.get(0).end() == 0x1004 && intervals.get(0).storage().available() &&
                    intervals.get(1).start() == 0x1004 && intervals.get(1).end() == 0x100c &&
                    !intervals.get(1).storage().available(), "invalid terminal prefix: " + intervals);
            }
            else {
                require(intervals.isEmpty(), "unsafe terminal prefix: " + intervals);
            }
        }
    }

    private static List<Instruction> replaceFirst(Fixture fixture, Instruction first) {
        var result = new ArrayList<>(fixture.instructions());
        result.set(0, first);
        return result;
    }

    private static PcodeOp operation(Instruction instruction, int opcode, Varnode[] inputs,
            Varnode output) {
        return new PcodeOp(instruction.getAddress(), 0, opcode, inputs, output);
    }

    private static Instruction decorate(Instruction original, String name, Object value) {
        return (Instruction) Proxy.newProxyInstance(Instruction.class.getClassLoader(),
            new Class<?>[] { Instruction.class }, (proxy, method, arguments) ->
                method.getName().equals(name) ? value : method.invoke(original, arguments));
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
        return (Program) Proxy.newProxyInstance(Program.class.getClassLoader(),
            new Class<?>[] { Program.class }, (proxy, method, arguments) ->
                method.getName().equals("getListing") ? listing : method.invoke(real, arguments));
    }

    private static Fixture fixture(String id, String encoded) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(id));
        Object owner = new Object();
        var program = new ProgramDB("opaque-effects", language, language.getDefaultCompilerSpec(), owner);
        boolean complete = false;
        try {
            int transaction = program.startTransaction("decode instruction fixture");
            try {
                byte[] code = HexFormat.of().parseHex(encoded);
                var start = language.getDefaultSpace().getAddress(0x1000);
                var body = new AddressSet(start, start.add(code.length - 1));
                var block = program.getMemory().createInitializedBlock("code", start,
                    code.length, (byte) 0, TaskMonitor.DUMMY, false);
                block.setExecute(true);
                program.getMemory().setBytes(start, code);
                if (id.startsWith("ARM:")) {
                    program.getProgramContext().setValue(program.getRegister("TMode"),
                        start, body.getMaxAddress(), BigInteger.ZERO);
                }
                require(new DisassembleCommand(start, body, true).applyTo(program, TaskMonitor.DUMMY),
                    "fixture disassembly failed: " + id);
                Function function = program.getFunctionManager().createFunction("fixture", start,
                    body, SourceType.USER_DEFINED);
                var instructions = new ArrayList<Instruction>();
                program.getListing().getInstructions(body, true).forEach(instructions::add);
                require(!instructions.isEmpty() && instructions.get(instructions.size() - 1)
                    .getMaxAddress().equals(body.getMaxAddress()), "fixture decode did not reach its end");
                complete = true;
                return new Fixture(program, function, List.copyOf(instructions), owner);
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
            Object owner) implements AutoCloseable {
        public void close() { program.release(owner); }
    }

    private static void unknown(Storage storage) {
        reason(storage, OmissionReason.UNKNOWN_LIFETIME);
        require(((UnavailableStorage) storage).diagnostic().contains("opaque instruction effects"),
            "opaque omission lost its diagnostic");
    }

    private static void reason(Storage storage, OmissionReason reason) {
        require(storage instanceof UnavailableStorage unavailable && unavailable.reason() == reason,
            "expected " + reason + " but found " + storage);
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
