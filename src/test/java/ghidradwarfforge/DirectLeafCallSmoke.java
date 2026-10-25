package ghidradwarfforge;

import java.io.File;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.RegisterStorage;

/** Actual decoded calls and adversarial effects; ABI declarations alone never suffice. */
public final class DirectLeafCallSmoke {
    private static int checks;

    private DirectLeafCallSmoke() {
    }

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (String target : List.of("x86_64", "aarch64")) {
            try (Fixture fixture = fixture(target)) {
                controls(fixture);
            }
            System.out.println("direct-leaf-call-target=PASS " + target);
        }
        System.out.println("direct-leaf-call-smoke=PASS checks=" + checks);
    }

    private static void controls(Fixture f) throws Exception {
        var caller = instructions(f.program(), f.caller());
        var leaf = instructions(f.program(), f.callee());
        Instruction call = caller.stream().filter(i -> i.getFlowType().isCall()).findFirst().orElseThrow();
        var evidence = DirectLeafCalls.inspect(f.program(), caller, TaskMonitor.DUMMY);
        require(evidence != null && evidence.size() == 1, "real direct call rejected");
        var saved = f.program().getRegister(f.target().equals("x86_64") ? "RBX" : "x19");
        require(evidence.get(call.getAddress()).preserves(saved, TaskMonitor.DUMMY), "leaf lost saved register");
        expect(f, f.program(), f.backupEnd());

        // Every effect is derived from decoded instructions and physical aliases,
        // including writes contrary to the selected convention's unaffected list.
        Varnode backup = new Varnode(saved.getAddress(), saved.getMinimumByteSize());
        var constant = new Varnode(f.program().getAddressFactory().getConstantSpace().getAddress(99),
            backup.getSize());
        PcodeOp write = new PcodeOp(leaf.get(0).getAddress(), 0, PcodeOp.COPY,
            new Varnode[] { constant }, backup);
        Instruction overwritten = decorate(leaf.get(0), Map.of("getPcode", new PcodeOp[] { write }));
        expect(f, replace(f.program(), overwritten), call.getFallThrough().getOffset());
        Instruction resultOnly = decorate(leaf.get(0), Map.of("getResultObjects", new Object[] { saved }));
        expect(f, replace(f.program(), resultOnly), call.getFallThrough().getOffset());
        var partial = new Varnode(backup.getAddress().add(1), 1);
        PcodeOp partialWrite = new PcodeOp(leaf.get(0).getAddress(), 0, PcodeOp.COPY,
            new Varnode[] { new Varnode(constant.getAddress(), 1) }, partial);
        expect(f, replace(f.program(), decorate(leaf.get(0),
            Map.of("getPcode", new PcodeOp[] { partialWrite }))), call.getFallThrough().getOffset());

        // The call instruction itself can write an ABI-unaffected register.
        var callWrites = new ArrayList<>(List.of(call.getPcode()));
        callWrites.add(0, write);
        expect(f, replace(f.program(), decorate(call,
            Map.of("getPcode", callWrites.toArray(PcodeOp[]::new)))), call.getFallThrough().getOffset());
        var undeclared = new DirectLeafCalls.Leaf(leaf, List.of());
        require(!undeclared.preserves(saved, TaskMonitor.DUMMY), "missing ABI contract accepted");
        var shortDeclaration = new DirectLeafCalls.Leaf(leaf,
            List.of(new Varnode(saved.getAddress(), saved.getMinimumByteSize() / 2)));
        require(!shortDeclaration.preserves(saved, TaskMonitor.DUMMY), "partial ABI declaration covered full base");

        for (Instruction subject : List.of(call, leaf.get(0))) {
            for (var change : List.of(Map.<String, Object>of("isLengthOverridden", true),
                    Map.<String, Object>of("isFallThroughOverridden", true),
                    Map.<String, Object>of("getFlowOverride", FlowOverride.CALL),
                    Map.<String, Object>of("isInDelaySlot", true),
                    Map.<String, Object>of("getDelaySlotDepth", 1),
                    Map.<String, Object>of("getParsedLength", subject.getLength() + 1))) {
                rejected(f, replace(f.program(), decorate(subject, change)));
            }
        }
        for (int opcode : new int[] { PcodeOp.CALLIND, PcodeOp.CALLOTHER,
                PcodeOp.UNIMPLEMENTED, PcodeOp.BRANCH, PcodeOp.CBRANCH, PcodeOp.BRANCHIND }) {
            PcodeOp opaque = new PcodeOp(leaf.get(0).getAddress(), 0, opcode,
                new Varnode[] { constant }, null);
            rejected(f, replace(f.program(), decorate(leaf.get(0),
                Map.of("getPcode", new PcodeOp[] { opaque }))));
        }
        PcodeOp recurse = new PcodeOp(leaf.get(0).getAddress(), 0, PcodeOp.CALL,
            new Varnode[] { new Varnode(f.caller().getEntryPoint(), 8) }, null);
        rejected(f, replace(f.program(), decorate(leaf.get(0),
            Map.of("getPcode", new PcodeOp[] { recurse }))));
        rejected(f, replace(f.program(), decorate(call, Map.of("getFlows", new Address[0]))));
        rejected(f, replace(f.program(), decorate(call,
            Map.of("getFlows", new Address[] { f.callee().getEntryPoint().add(1) }))));
        rejected(f, replace(f.program(), decorate(call,
            Map.of("getFlowType", RefType.COMPUTED_CALL))));
        rejected(f, replace(f.program(), decorate(call,
            Map.of("getFlowType", RefType.CONDITIONAL_CALL))));
        var callOps = new ArrayList<>(List.of(call.getPcode()));
        PcodeOp direct = callOps.stream().filter(op -> op.getOpcode() == PcodeOp.CALL).findFirst().orElseThrow();
        callOps.add(direct);
        rejected(f, replace(f.program(), decorate(call,
            Map.of("getPcode", callOps.toArray(PcodeOp[]::new)))));
        rejected(f, replace(f.program(), decorate(leaf.get(leaf.size() - 1),
            Map.of("getPcode", new PcodeOp[0]))));
        PcodeOp registerStore = new PcodeOp(leaf.get(0).getAddress(), 0, PcodeOp.STORE,
            new Varnode[] {
                new Varnode(constant.getAddress().getAddressSpace().getAddress(
                    Integer.toUnsignedLong(backup.getAddress().getAddressSpace().getSpaceID())), 4),
                constant, backup }, null);
        rejected(f, replace(f.program(), decorate(leaf.get(0),
            Map.of("getPcode", new PcodeOp[] { registerStore }))));

        int transaction = f.program().startTransaction("unsupported callee metadata");
        try {
            f.callee().setCallingConvention("unknown");
            rejected(f, f.program());
            f.callee().setCallingConvention(f.program().getCompilerSpec().getDefaultCallingConvention().getName());
            f.callee().setCallFixup("unproven-fixture-fixup");
            rejected(f, f.program());
            f.callee().setCallFixup(null);
            f.callee().setNoReturn(true);
            rejected(f, f.program());
        }
        finally {
            f.program().endTransaction(transaction, false);
        }
        TaskMonitorAdapter cancelled = new TaskMonitorAdapter();
        cancelled.setCancelEnabled(true);
        cancelled.cancel();
        try {
            DirectLeafCalls.inspect(f.program(), caller, cancelled);
            throw new AssertionError("cancelled call inspection completed");
        }
        catch (CancelledException expected) {
            checks++;
        }
    }

    private static void expect(Fixture f, Program program, long backupEnd) throws Exception {
        var parameter = new ParameterImpl("value", IntegerDataType.dataType,
            program.getRegister(f.target().equals("x86_64") ? "EDI" : "w0"), program);
        var map = TargetRegisterMap.forTarget(f.target());
        var rejected = GhidraVariableStorage.stableParameter(program, f.caller(), parameter, map, TaskMonitor.DUMMY);
        var intervals = GhidraVariableStorage.parameterPrefix(program, f.caller(), parameter,
            map, rejected, TaskMonitor.DUMMY);
        require(intervals.size() == 3 && intervals.get(0).start() == 0x1000 &&
            intervals.get(0).end() == f.handoff() && intervals.get(1).start() == f.handoff() &&
            intervals.get(1).end() == backupEnd && intervals.get(1).storage() instanceof RegisterStorage saved &&
            saved.bitSize() == 32 && saved.valueBitOffset() == 0 &&
            intervals.get(2).start() == backupEnd && !intervals.get(2).storage().available(),
            "wrong call backup intervals: " + intervals);
    }

    private static void rejected(Fixture f, Program program) throws Exception {
        require(DirectLeafCalls.inspect(program, instructions(program, f.caller()), TaskMonitor.DUMMY) == null,
            "unsupported call proof accepted");
        var parameter = new ParameterImpl("value", IntegerDataType.dataType,
            program.getRegister(f.target().equals("x86_64") ? "EDI" : "w0"), program);
        var map = TargetRegisterMap.forTarget(f.target());
        var original = GhidraVariableStorage.stableParameter(program, f.caller(), parameter, map, TaskMonitor.DUMMY);
        require(GhidraVariableStorage.parameterPrefix(program, f.caller(), parameter, map,
            original, TaskMonitor.DUMMY).isEmpty(), "public extraction bypassed rejected call evidence");
    }

    private static Fixture fixture(String target) throws Exception {
        boolean x86 = target.equals("x86_64");
        var language = DefaultLanguageService.getLanguageService().getLanguage(
            new LanguageID(x86 ? "x86:LE:64:default" : "AARCH64:LE:64:v8A"));
        Object owner = new Object();
        ProgramDB program = new ProgramDB("direct-leaf-call", language, language.getDefaultCompilerSpec(), owner);
        boolean complete = false;
        try {
            int transaction = program.startTransaction("decoded direct call fixture");
            try {
                // Save/restore the backup and return address, change the incoming
                // argument, call a leaf that doubles it, then add the saved value.
                String caller = x86 ? "5389fb83c703e8f500000001d85bc3"
                    : "fd7bbea9fd030091f35301a9f303002a000c00113b0000946002000bf35341a9fd7bc2a8c0035fd6";
                Function first = function(program, "caller", 0x1000, caller);
                Function second = function(program, "callee", 0x1100,
                    x86 ? "8d043fc3" : "0000000bc0035fd6");
                complete = true;
                return new Fixture(target, program, first, second, owner,
                    x86 ? 0x1006 : 0x1014, x86 ? 0x100e : 0x1020);
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

    private static Function function(ProgramDB program, String name, long offset, String hex) throws Exception {
        byte[] code = HexFormat.of().parseHex(hex);
        Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
        var body = new AddressSet(start, start.add(code.length - 1));
        var block = program.getMemory().createInitializedBlock(name, start, code.length,
            (byte) 0, TaskMonitor.DUMMY, false);
        block.setExecute(true);
        program.getMemory().setBytes(start, code);
        require(new DisassembleCommand(start, body, true).applyTo(program, TaskMonitor.DUMMY),
            "fixture did not decode");
        var function = program.getFunctionManager().createFunction(name, start, body, SourceType.USER_DEFINED);
        function.setCallingConvention(program.getCompilerSpec().getDefaultCallingConvention().getName());
        return function;
    }

    private record Fixture(String target, ProgramDB program, Function caller, Function callee,
            Object owner, long handoff, long backupEnd) implements AutoCloseable {
        public void close() { program.release(owner); }
    }

    private static List<Instruction> instructions(Program program, Function function) {
        var result = new ArrayList<Instruction>();
        program.getListing().getInstructions(function.getBody(), true).forEach(result::add);
        return List.copyOf(result);
    }

    private static Instruction decorate(Instruction original, Map<String, Object> changes) {
        return (Instruction) Proxy.newProxyInstance(Instruction.class.getClassLoader(),
            new Class<?>[] { Instruction.class }, (proxy, method, arguments) ->
                changes.containsKey(method.getName()) ? changes.get(method.getName()) : method.invoke(original, arguments));
    }

    private static Program replace(Program real, Instruction replacement) {
        Listing listing = (Listing) Proxy.newProxyInstance(Listing.class.getClassLoader(),
            new Class<?>[] { Listing.class }, (proxy, method, arguments) -> {
                if (!method.getName().equals("getInstructions")) {
                    return method.invoke(real.getListing(), arguments);
                }
                var original = (InstructionIterator) method.invoke(real.getListing(), arguments);
                return new InstructionIterator() {
                    public boolean hasNext() { return original.hasNext(); }
                    public Instruction next() {
                        Instruction instruction = original.next();
                        return instruction.getAddress().equals(replacement.getAddress()) ? replacement : instruction;
                    }
                    public Iterator<Instruction> iterator() { return this; }
                };
            });
        return (Program) Proxy.newProxyInstance(Program.class.getClassLoader(),
            new Class<?>[] { Program.class }, (proxy, method, arguments) ->
                method.getName().equals("getListing") ? listing : method.invoke(real, arguments));
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
