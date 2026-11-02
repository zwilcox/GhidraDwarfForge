package ghidradwarfforge;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.RegisterStorage;
import ghidradwarfforge.locations.VariableStorageModel.UnavailableStorage;

/** Actual delay-slot decoding, incoming value boundaries and malformed-tail controls. */
public final class DelayedReturnPrefixSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (boolean big : List.of(true, false)) {
            for (String variant : List.of("32:default", "64:64-32addr", "64:default")) {
                for (boolean delayedWrite : List.of(true, false)) {
                    var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(
                        "MIPS:" + (big ? "BE" : "LE") + ":" + variant));
                    Object owner = new Object();
                    var program = new ProgramDB("delayed-prefix", language,
                        language.getCompilerSpecByID(new CompilerSpecID(variant.endsWith("32addr") ? "n32" : "default")), owner);
                    int transaction = program.startTransaction("fixture");
                    try {
                        boolean wide = variant.startsWith("64");
                        var bytes = ByteBuffer.allocate(12).order(big ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
                        int add = wide ? 0x0085202d : 0x00852021;
                        bytes.putInt(delayedWrite ? 0 : add).putInt(0x03e00008).putInt(delayedWrite ? add : 0);
                        var entry = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
                        var memory = program.getMemory().createInitializedBlock("code", entry, 12, (byte) 0, TaskMonitor.DUMMY, false);
                        memory.setExecute(true);
                        program.getMemory().setBytes(entry, bytes.array());
                        require(new DisassembleCommand(entry, null, true).applyTo(program), "decode failed");
                        Function function = program.getFunctionManager().createFunction("value", entry,
                            new AddressSet(entry, entry.add(11)), SourceType.USER_DEFINED);
                        function.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
                        DataType type = wide ? new LongLongDataType(program.getDataTypeManager()) :
                            new IntegerDataType(program.getDataTypeManager());
                        function.addParameter(new ParameterImpl("value", type, program), SourceType.USER_DEFINED);
                        var parameter = function.getParameter(0);
                        var registers = TargetRegisterMap.forTarget(wide && !variant.endsWith("32addr") ?
                            (big ? "mips64" : "mips64el") : (big ? "mips" : "mipsel"));
                        var stable = GhidraVariableStorage.stableParameter(program, function, parameter, registers, TaskMonitor.DUMMY);
                        require(stable instanceof UnavailableStorage, "write incorrectly stable");
                        var prefix = GhidraVariableStorage.parameterPrefix(program, function, parameter, registers, stable, TaskMonitor.DUMMY);
                        require(!prefix.isEmpty(), "delayed return prevented entry prefix");
                        long boundary = delayedWrite ? 0x1008 : 0x1004;
                        require(prefix.getFirst().start() == 0x1000 && prefix.getFirst().end() == boundary &&
                            prefix.getFirst().storage() instanceof RegisterStorage, "incoming boundary incorrect");
                        require(prefix.getLast().end() == 0x100c && !prefix.getLast().storage().available(), "clobber tail exposed");
                        var instructions = new ArrayList<Instruction>();
                        for (var instruction : program.getListing().getInstructions(function.getBody(), true)) instructions.add(instruction);
                        require(instructions.size() == 3 && instructions.get(1).getDelaySlotDepth() == 1 &&
                            instructions.get(2).isInDelaySlot(), "not actual delayed decoding");
                        var base = program.getRegister("a0");
                        require(GhidraVariableStorage.registerPrefixEnd(0x1000, 0x100c, instructions, base, TaskMonitor.DUMMY) == boundary,
                            "raw boundary differs");
                        for (var mutation : List.<Map<String, Object>>of(
                                Map.of("isInDelaySlot", false), Map.of("getDelaySlotDepth", 1),
                                Map.of("getFlowOverride", FlowOverride.BRANCH), Map.of("isLengthOverridden", true),
                                Map.of("isFallThroughOverridden", true), Map.of("getFlowType", RefType.UNCONDITIONAL_JUMP),
                                Map.of("getParsedLength", 8))) {
                            var invalid = new ArrayList<>(instructions);
                            invalid.set(2, decorate(instructions.get(2), mutation));
                            require(GhidraVariableStorage.registerPrefixEnd(0x1000, 0x100c, invalid, base, TaskMonitor.DUMMY) < 0,
                                "malformed delay accepted: " + mutation);
                        }
                        var missing = instructions.subList(0, 2);
                        require(GhidraVariableStorage.registerPrefixEnd(0x1000, 0x100c, missing, base, TaskMonitor.DUMMY) < 0,
                            "missing slot accepted");
                        var wrongOwner = new ArrayList<>(instructions);
                        wrongOwner.set(1, decorate(instructions.get(1), Map.of("getFlowType", RefType.UNCONDITIONAL_JUMP)));
                        require(GhidraVariableStorage.registerPrefixEnd(0x1000, 0x100c, wrongOwner, base, TaskMonitor.DUMMY) < 0,
                            "delayed jump treated as return");
                        program.getReferenceManager().addMemoryReference(entry.add(0x100), entry.add(4),
                            RefType.UNCONDITIONAL_JUMP, SourceType.USER_DEFINED, 0);
                        require(GhidraVariableStorage.parameterPrefix(program, function, parameter, registers, stable,
                            TaskMonitor.DUMMY).isEmpty(), "second entry accepted");
                    }
                    finally {
                        program.endTransaction(transaction, true);
                        program.release(owner);
                    }
                }
            }
        }
        System.out.println("delayed-return-prefix-smoke=PASS checks=" + checks);
    }

    private static Instruction decorate(Instruction real, Map<String, Object> replacements) {
        return (Instruction) Proxy.newProxyInstance(Instruction.class.getClassLoader(), new Class<?>[] { Instruction.class },
            (proxy, method, args) -> {
                if (replacements.containsKey(method.getName())) return replacements.get(method.getName());
                try { return method.invoke(real, args); }
                catch (InvocationTargetException error) { throw error.getCause(); }
            });
    }

    private static void require(boolean value, String message) {
        checks++;
        if (!value) throw new AssertionError(message);
    }
}
