package ghidradwarfforge;

import java.io.File;
import java.util.HexFormat;
import java.util.List;

import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.RegisterStorage;
import ghidradwarfforge.locations.VariableStorageModel.Storage;

/** Real predicated instructions must not turn a possible copy into a definite value. */
public final class IntraInstructionFlowSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (String language : List.of("ARM:LE:32:v8", "ARM:LEBE:32:v8LEInstruction")) {
            for (String shape : List.of("conditional-copy", "backup", "conditional-store", "unrelated",
                    "self-copy", "overwrite", "release", "unknown-store")) check(language, shape);
        }
        System.out.println("intra-instruction-flow-smoke=PASS checks=" + checks);
    }

    private static void check(String id, String shape) throws Exception {
        // ARM-state instruction bytes are little endian in both selected languages.
        String prefix = "10d04de2"; // sub stack pointer, stack pointer, #16
        String conditional;
        String suffix = "";
        boolean survives;
        int expectedRegister;
        switch (shape) {
            case "conditional-copy" -> {
                conditional = "0040a001"; // moveq r4,r0
                suffix = "0000a0e3"; // mov r0,#0
                survives = false; expectedRegister = -1;
            }
            case "backup" -> {
                prefix += "0040a0e1"; // mov r4,r0
                conditional = "0000a003"; // moveq r0,#0
                survives = true; expectedRegister = 4;
            }
            case "conditional-store" -> {
                conditional = "04008d05"; // streq r0,[stack pointer,#4]
                suffix = "0000a0e3";
                survives = false; expectedRegister = -1;
            }
            case "overwrite" -> {
                prefix += "04008de50000a0e3"; // definite spill then kill original
                conditional = "04108d05"; // streq r1,[stack pointer,#4]
                survives = false; expectedRegister = -1;
            }
            case "release" -> {
                prefix += "04008de50000a0e3";
                conditional = "10d08d02"; // addeq stack pointer,stack pointer,#16
                survives = false; expectedRegister = -1;
            }
            case "unknown-store" -> {
                prefix += "04008de50000a0e3";
                conditional = "00208105"; // streq r2,[r1]
                survives = false; expectedRegister = -1;
            }
            case "self-copy" -> {
                conditional = "0000a001"; // moveq r0,r0
                survives = true; expectedRegister = 0;
            }
            default -> {
                conditional = "0010a013"; // movne r1,#0
                survives = true; expectedRegister = 0;
            }
        }
        int predicateOffset = prefix.length() / 2;
        int observedOffset = predicateOffset + 4 + suffix.length() / 2;
        byte[] bytes = HexFormat.of().parseHex(prefix + conditional + suffix + "00f020e310d08de21eff2fe1");
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(id));
        Object owner = new Object();
        var program = new ProgramDB("predicate", language, language.getDefaultCompilerSpec(), owner);
        try {
            int transaction = program.startTransaction("predicated transfer");
            try {
                var entry = language.getDefaultSpace().getAddress(0x1000);
                var body = new AddressSet(entry, entry.add(bytes.length - 1));
                var block = program.getMemory().createInitializedBlock("code", entry, bytes.length,
                    (byte) 0, TaskMonitor.DUMMY, false);
                block.setExecute(true);
                program.getMemory().setBytes(entry, bytes);
                require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY), "decode");
                var function = program.getFunctionManager().createFunction("conditional", entry, body, SourceType.USER_DEFINED);
                function.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.USER_DEFINED,
                    new ParameterImpl("value", IntegerDataType.dataType, program.getRegister("r0"), program, SourceType.USER_DEFINED));
                var instruction = program.getListing().getInstructionAt(entry.add(predicateOffset));
                require(IntraInstructionFlow.targets(instruction, TaskMonitor.DUMMY) != null, "predicate rejected " + instruction + " flow=" + instruction.getFlowType() + " default=" + java.util.Arrays.toString(instruction.getDefaultFlows()) + " refs=" + java.util.Arrays.toString(instruction.getFlows()) + " pcode=" + java.util.Arrays.toString(instruction.getPcode()));
                require(RegisterDefinitionFlow.decodedInstructions(program, function, true, true, TaskMonitor.DUMMY).isEmpty(),
                    "callee/local decoder acquired unproved conditional effects");
                var map = TargetRegisterMap.forTarget("arm");
                var intervals = StackValueFlow.prove(program, function, function.getParameter(0), map, TaskMonitor.DUMMY);
                String context = id + "/" + shape + ": " + intervals;
                require(!intervals.isEmpty() && at(intervals, 0) instanceof RegisterStorage, "incoming value missing " + context);
                Storage after = at(intervals, observedOffset);
                require(after.available() == survives, "must-path availability " + context);
                if (survives) require(after instanceof RegisterStorage register &&
                    register.register().dwarfNumber() == expectedRegister, "wrong surviving register " + context);
                instruction.setFlowOverride(FlowOverride.RETURN);
                require(StackValueFlow.prove(program, function, function.getParameter(0), map, TaskMonitor.DUMMY).isEmpty(),
                    "flow override accepted");
                instruction.setFlowOverride(FlowOverride.NONE);
                instruction.setFallThrough(entry);
                require(StackValueFlow.prove(program, function, function.getParameter(0), map, TaskMonitor.DUMMY).isEmpty(),
                    "fallthrough override accepted");
                instruction.clearFallThroughOverride();
                require(StackValueFlow.prove(program, function, function.getParameter(0), map, TaskMonitor.DUMMY).equals(intervals),
                    "controls changed original proof");
                malformed(program);
                internalPaths(program, program.getListing().getInstructionAt(entry.add(observedOffset)), map);
                var cancelled = new TaskMonitorAdapter(true); cancelled.cancel();
                try {
                    StackValueFlow.prove(program, function, function.getParameter(0), map, cancelled);
                    throw new AssertionError("cancel ignored");
                }
                catch (ghidra.util.exception.CancelledException expected) { checks++; }
            }
            finally { program.endTransaction(transaction, true); }
        }
        finally { program.release(owner); }
    }

    private static void internalPaths(ProgramDB program, ghidra.program.model.listing.Instruction template,
            TargetRegisterMap map) throws Exception {
        var constantSpace = program.getAddressFactory().getConstantSpace();
        var uniqueSpace = program.getAddressFactory().getUniqueSpace();
        var address = template.getAddress();
        var source = new Varnode(program.getRegister("r0").getAddress(), 4);
        var first = new Varnode(program.getRegister("r4").getAddress(), 4);
        var second = new Varnode(program.getRegister("r5").getAddress(), 4);
        var temporary = new Varnode(uniqueSpace.getAddress(0x100), 4);
        var condition = new Varnode(program.getRegister("ZR").getAddress(), 1);
        var zero = new Varnode(constantSpace.getAddress(0), 4);
        for (boolean disagreement : new boolean[] {false, true}) {
            PcodeOp[] operations = {
                new PcodeOp(address, 0, PcodeOp.COPY, new Varnode[] {source}, temporary),
                new PcodeOp(address, 1, PcodeOp.CBRANCH,
                    new Varnode[] {new Varnode(constantSpace.getAddress(3), 4), condition}, null),
                new PcodeOp(address, 2, PcodeOp.COPY, new Varnode[] {temporary}, first),
                new PcodeOp(address, 3, PcodeOp.BRANCH,
                    new Varnode[] {new Varnode(constantSpace.getAddress(2), 4)}, null),
                new PcodeOp(address, 4, PcodeOp.COPY, new Varnode[] {disagreement ? zero : temporary}, first),
                new PcodeOp(address, 5, PcodeOp.COPY, new Varnode[] {first}, second),
                new PcodeOp(address, 6, PcodeOp.COPY, new Varnode[] {zero}, source),
                new PcodeOp(address, 7, PcodeOp.COPY, new Varnode[] {zero}, first)
            };
            var instruction = (ghidra.program.model.listing.Instruction) java.lang.reflect.Proxy.newProxyInstance(
                ghidra.program.model.listing.Instruction.class.getClassLoader(),
                new Class<?>[] {ghidra.program.model.listing.Instruction.class}, (proxy, method, arguments) ->
                    method.getName().equals("getPcode") ? operations : method.invoke(template, arguments));
            var state = StackValueFlow.forIncomingPiece(program, source);
            require(IntraInstructionFlow.targets(instruction, TaskMonitor.DUMMY) != null, "forward DAG rejected");
            require(state.advance(instruction, false, TaskMonitor.DUMMY), "forward DAG transfer rejected");
            Storage value = state.location(map);
            require(value.available() == !disagreement, "conditional facts were unioned or lost");
            if (!disagreement) require(value instanceof RegisterStorage register && register.register().dwarfNumber() == 5,
                "temporary/merge/forward branch did not preserve the common copy");
        }
    }

    private static void malformed(ProgramDB program) throws Exception {
        var address = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
        var constants = program.getAddressFactory().getConstantSpace();
        var register = program.getRegister("r0");
        var output = new Varnode(register.getAddress(), 4);
        var condition = new Varnode(program.getRegister("ZR").getAddress(), 1);
        var copy = new PcodeOp(address, 1, PcodeOp.COPY, new Varnode[] { output }, output);
        for (long distance : new long[] { 0, -1, 3, Long.MAX_VALUE }) {
            var branch = new PcodeOp(address, 0, PcodeOp.CBRANCH,
                new Varnode[] { new Varnode(constants.getAddress(distance), 4), condition }, null);
            require(IntraInstructionFlow.targets(new PcodeOp[] { branch, copy }, TaskMonitor.DUMMY) == null,
                "invalid branch distance " + distance);
        }
        for (int opcode : new int[] { PcodeOp.BRANCH, PcodeOp.CBRANCH }) {
            var target = new Varnode(constants.getAddress(2), 4);
            var inputs = opcode == PcodeOp.BRANCH ? new Varnode[] { target } : new Varnode[] { target, condition };
            var branch = new PcodeOp(address, 0, opcode, inputs, null);
            require(IntraInstructionFlow.targets(new PcodeOp[] { branch, copy }, TaskMonitor.DUMMY)[0] == 2,
                "branch to instruction exit rejected");
            for (int forbidden : new int[] { PcodeOp.CALL, PcodeOp.CALLIND, PcodeOp.BRANCHIND,
                    PcodeOp.CALLOTHER, PcodeOp.RETURN, PcodeOp.UNIMPLEMENTED }) {
                var hidden = new PcodeOp(address, 1, forbidden, new Varnode[] { target }, null);
                require(IntraInstructionFlow.targets(new PcodeOp[] { branch, hidden }, TaskMonitor.DUMMY) == null,
                    "hidden control admitted " + forbidden);
            }
            require(IntraInstructionFlow.targets(new PcodeOp[] {
                new PcodeOp(address, 0, opcode, inputs, output), copy }, TaskMonitor.DUMMY) == null, "branch output accepted");
        }
        require(IntraInstructionFlow.targets(new PcodeOp[] {
            new PcodeOp(address, 0, PcodeOp.CBRANCH, new Varnode[] { new Varnode(address, 4), condition }, null), copy },
            TaskMonitor.DUMMY) == null, "machine address accepted as internal branch");
    }

    private static Storage at(List<GhidraVariableStorage.StorageInterval> intervals, long offset) {
        return intervals.stream().filter(row -> row.start() <= 0x1000 + offset && row.end() > 0x1000 + offset)
            .findFirst().orElseThrow().storage();
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
