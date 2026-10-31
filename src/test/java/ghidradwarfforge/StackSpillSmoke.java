package ghidradwarfforge;

import java.io.File;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
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
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.RegisterRelativeStorage;

/** Real decoder positives and independent ordered-pcode lifetime controls. */
public final class StackSpillSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (String target : List.of("x86_64", "aarch64")) {
            for (int width : new int[] { 4, 8 }) {
                check(target, width);
            }
        }
        System.out.println("stack-spill-smoke=PASS checks=" + checks);
    }

    private static void check(String target, int width) throws Exception {
        boolean x86 = target.equals("x86_64");
        var language = DefaultLanguageService.getLanguageService().getLanguage(
            new LanguageID(x86 ? "x86:LE:64:default" : "AARCH64:LE:64:v8A"));
        String hex = x86 ? (width == 4 ? "897c24fc9031ff908b4424fcc3" : "48897c24f8904831ff90488b4424f8c3") :
            (width == 4 ? "ff4300d1e00f00b91f2003d5e0031faa1f2003d5e00f40b9ff430091c0035fd6" :
                "ff4300d1e00700f91f2003d5e0031faa1f2003d5e00740f9ff430091c0035fd6");
        byte[] bytes = HexFormat.of().parseHex(hex);
        Object owner = new Object();
        var program = new ProgramDB("spill", language, language.getDefaultCompilerSpec(), owner);
        try {
            int transaction = program.startTransaction("stack spill model");
            try {
                var address = language.getDefaultSpace().getAddress(0x1000);
                var body = new AddressSet(address, address.add(bytes.length - 1));
                var block = program.getMemory().createInitializedBlock("code", address, bytes.length,
                    (byte) 0, TaskMonitor.DUMMY, false);
                block.setExecute(true);
                program.getMemory().setBytes(address, bytes);
                require(new DisassembleCommand(address, body, true).applyTo(program, TaskMonitor.DUMMY), "decode");
                Function function = program.getFunctionManager().createFunction("spill", address, body,
                    SourceType.USER_DEFINED);
                var type = width == 4 ? IntegerDataType.dataType : LongLongDataType.dataType;
                function.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE, true,
                    SourceType.USER_DEFINED, new ParameterImpl("value", type,
                        program.getRegister(x86 ? (width == 4 ? "EDI" : "RDI") : (width == 4 ? "w0" : "x0")),
                        program, SourceType.USER_DEFINED));
                Parameter parameter = function.getParameter(0);
                var instructions = new ArrayList<Instruction>();
                program.getListing().getInstructions(body, true).forEach(instructions::add);
                var mapping = TargetRegisterMap.forTarget(target);
                Varnode incoming = parameter.getVariableStorage().getFirstVarnode();
                long end = 0x1000 + bytes.length;
                int spillIndex = x86 ? 0 : 1;
                int killIndex = x86 ? 2 : 3;
                int afterIndex = killIndex + 1;
                long handoff = instructions.get(killIndex).getMaxAddress().getOffset() + 1;
                long expectedEnd = x86 ? end : end - 4;
                long offset = x86 ? -width : 16 - width;
                var backup = StackSpillLifetime.prove(program, 0x1000, end, instructions,
                    incoming, width, mapping, TaskMonitor.DUMMY);
                require(backup != null && backup.end() == expectedEnd && backup.storage().byteOffset() == offset,
                    "real spill failed: " + target + " " + width + " " + backup);
                var rejected = GhidraVariableStorage.stableParameter(program, function, parameter, mapping, TaskMonitor.DUMMY);
                var intervals = GhidraVariableStorage.parameterPrefix(program, function, parameter, mapping,
                    rejected, TaskMonitor.DUMMY);
                require(intervals.size() == (x86 ? 2 : 3) && intervals.get(1).start() == handoff &&
                    intervals.get(1).end() == expectedEnd && intervals.get(1).storage().equals(backup.storage()),
                    "public extraction lacks exact register-to-stack handoff: " + intervals);
                if (!x86) {
                    require(intervals.getLast().storage() instanceof ghidradwarfforge.locations.VariableStorageModel.RegisterStorage reloaded &&
                        reloaded.register().dwarfNumber() == 0,
                        "SP change retires stack storage but preserves the completed reload: " + intervals);
                }
                var noMap = new TargetRegisterMap(target, "negative SP map", java.util.Map.of(incoming.toString(), 0));
                require(StackSpillLifetime.prove(program, 0x1000, end, instructions, incoming, width,
                    noMap, TaskMonitor.DUMMY) == null, "unmapped stack pointer accepted");
                Instruction spill = instructions.get(spillIndex);
                PcodeOp store = Arrays.stream(spill.getPcode()).filter(op -> op.getOpcode() == PcodeOp.STORE)
                    .findFirst().orElseThrow();
                for (int kind = 0; kind < 9; kind++) {
                    var operations = new ArrayList<>(Arrays.asList(spill.getPcode()));
                    int storeIndex = 0;
                    while (operations.get(storeIndex).getOpcode() != PcodeOp.STORE) {
                        storeIndex++;
                    }
                    switch (kind) {
                        case 0 -> operations.remove(storeIndex);
                        case 1 -> operations.set(storeIndex, op(spill, PcodeOp.STORE, null,
                            store.getInput(0), store.getInput(1), constant(program, 7, width)));
                        case 2 -> operations.set(storeIndex, op(spill, PcodeOp.STORE, null,
                            store.getInput(0), constant(program, 0x7000, 8), store.getInput(2)));
                        case 3 -> operations.set(storeIndex, op(spill, PcodeOp.STORE, null,
                            store.getInput(0), store.getInput(1), new Varnode(incoming.getAddress(), width / 2)));
                        case 4 -> operations.add(store);
                        case 5 -> operations.add(op(spill, PcodeOp.COPY, incoming, constant(program, 0, width)));
                        case 6 -> {
                            var pointer = program.getCompilerSpec().getStackPointer();
                            operations.add(op(spill, PcodeOp.COPY,
                                new Varnode(pointer.getAddress(), pointer.getMinimumByteSize()), constant(program, 0, 8)));
                        }
                        case 7 -> operations.add(storeIndex, op(spill, PcodeOp.COPY,
                            new Varnode(store.getInput(1).getAddress().add(1), 1), constant(program, 0, 1)));
                        case 8 -> operations.set(storeIndex, op(spill, PcodeOp.STORE, null,
                            constant(program, 0x12345678, 4), store.getInput(1), store.getInput(2)));
                        default -> throw new AssertionError();
                    }
                    require(StackSpillLifetime.prove(program, 0x1000, end,
                        replace(instructions, spillIndex, decorate(spill, "getPcode", operations.toArray(PcodeOp[]::new))),
                        incoming, width, mapping, TaskMonitor.DUMMY) == null, "bad spill accepted " + kind);
                }
                Varnode temporary = new Varnode(program.getAddressFactory().getUniqueSpace().getAddress(0x100000), width);
                Varnode pointerTemporary = new Varnode(temporary.getAddress().add(0x100), 8);
                var pointer = program.getCompilerSpec().getStackPointer();
                Varnode pointerNode = new Varnode(pointer.getAddress(), pointer.getMinimumByteSize());
                PcodeOp copy = op(spill, PcodeOp.COPY, temporary, incoming);
                PcodeOp indirectStore = op(spill, PcodeOp.STORE, null, store.getInput(0), pointerNode, temporary);
                var partial = new PcodeOp[] { copy,
                    op(spill, PcodeOp.COPY, new Varnode(temporary.getAddress().add(1), 1), constant(program, 0, 1)),
                    indirectStore };
                require(StackSpillLifetime.prove(program, 0x1000, end,
                    replace(instructions, spillIndex, decorate(spill, "getPcode", partial)), incoming, width,
                    mapping, TaskMonitor.DUMMY) == null, "partial unique write retained a stale value");
                var leaked = replace(instructions, spillIndex, decorate(spill, "getPcode", new PcodeOp[] { copy }));
                leaked = replace(leaked, spillIndex + 1, decorate(instructions.get(spillIndex + 1),
                    "getPcode", new PcodeOp[] { indirectStore }));
                require(StackSpillLifetime.prove(program, 0x1000, end, leaked, incoming, width,
                    mapping, TaskMonitor.DUMMY) == null, "unique temporary leaked between instructions");
                var overflow = new PcodeOp[] {
                    op(spill, PcodeOp.INT_ADD, pointerTemporary, pointerNode, constant(program, Long.MAX_VALUE, 8)),
                    op(spill, PcodeOp.INT_ADD, pointerTemporary, pointerTemporary, constant(program, 1, 8)),
                    op(spill, PcodeOp.STORE, null, store.getInput(0), pointerTemporary, incoming) };
                require(StackSpillLifetime.prove(program, 0x1000, end,
                    replace(instructions, spillIndex, decorate(spill, "getPcode", overflow)), incoming, width,
                    mapping, TaskMonitor.DUMMY) == null, "overflowing stack displacement accepted");
                // Any later STORE may alias the stack, even at an unrelated-looking address.
                Instruction after = instructions.get(afterIndex);
                PcodeOp laterStore = op(after, PcodeOp.STORE, null, store.getInput(0),
                    constant(program, 0x7000, 8), constant(program, 0, width));
                for (Instruction changed : List.of(
                        decorate(after, "getPcode", new PcodeOp[] { laterStore }),
                        decorate(after, "getResultObjects", new Object[] { address.add(0x2000) }),
                        decorate(after, "getPcode", new PcodeOp[] {
                            op(after, PcodeOp.COPY, new Varnode(address.add(0x2000), width), constant(program, 0, width)) }),
                        decorate(after, "getResultObjects", new Object[] { program.getCompilerSpec().getStackPointer() }))) {
                    var limited = StackSpillLifetime.prove(program, 0x1000, end,
                        replace(instructions, afterIndex, changed), incoming, width, mapping, TaskMonitor.DUMMY);
                    require(limited != null && limited.end() == after.getMaxAddress().getOffset() + 1,
                        "later memory/SP effect did not end spill");
                }
                Instruction beforeKill = instructions.get(killIndex - 1);
                require(StackSpillLifetime.prove(program, 0x1000, end,
                    replace(instructions, killIndex - 1, decorate(beforeKill, "getPcode", new PcodeOp[] { laterStore })),
                    incoming, width, mapping, TaskMonitor.DUMMY) == null, "dead pre-handoff spill accepted");
                for (String property : List.of("isLengthOverridden", "isFallThroughOverridden", "isInDelaySlot")) {
                    require(StackSpillLifetime.prove(program, 0x1000, end,
                        replace(instructions, afterIndex, decorate(after, property, true)), incoming, width,
                        mapping, TaskMonitor.DUMMY) == null, "unsupported boundary accepted " + property);
                }
                var cancelled = new TaskMonitorAdapter(true);
                cancelled.cancel();
                try {
                    StackSpillLifetime.prove(program, 0x1000, end, instructions, incoming, width, mapping, cancelled);
                    throw new AssertionError("cancel ignored");
                }
                catch (CancelledException expected) {
                    checks++;
                }
                program.getReferenceManager().addMemoryReference(address.add(0x2000),
                    instructions.get(afterIndex).getAddress(), RefType.UNCONDITIONAL_JUMP, SourceType.USER_DEFINED, 0);
                require(GhidraVariableStorage.parameterPrefix(program, function, parameter, mapping,
                    rejected, TaskMonitor.DUMMY).isEmpty(), "secondary entry bypassed spill");
            }
            finally {
                program.endTransaction(transaction, true);
            }
        }
        finally {
            program.release(owner);
        }
    }

    private static Varnode constant(ProgramDB program, long value, int size) {
        return new Varnode(program.getAddressFactory().getConstantSpace().getAddress(value), size);
    }

    private static PcodeOp op(Instruction instruction, int code, Varnode output, Varnode... inputs) {
        return new PcodeOp(instruction.getAddress(), 0, code, inputs, output);
    }

    private static Instruction decorate(Instruction instruction, String name, Object value) {
        return (Instruction) Proxy.newProxyInstance(Instruction.class.getClassLoader(),
            new Class<?>[] { Instruction.class }, (proxy, method, arguments) ->
                method.getName().equals(name) ? value : method.invoke(instruction, arguments));
    }

    private static List<Instruction> replace(List<Instruction> instructions, int index, Instruction replacement) {
        var copy = new ArrayList<>(instructions);
        copy.set(index, replacement);
        return copy;
    }

    private static void require(boolean value, String detail) {
        checks++;
        if (!value) {
            throw new AssertionError(detail);
        }
    }
}
