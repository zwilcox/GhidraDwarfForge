package ghidradwarfforge;

import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.OmissionReason;
import ghidradwarfforge.locations.VariableStorageModel.UnavailableStorage;

/** Real listing references must preserve the incoming-value entry contract. */
public final class FlowEntryContractSmoke {
    private static int checks;

    private record Profile(String language, String target, String register, String code,
            Set<Integer> starts, Set<Integer> slots) { }

    private FlowEntryContractSmoke() { }

    static void check() throws Exception {
        checks = 0;
        int cases = 0;
        for (var profile : List.of(
                new Profile("x86:LE:64:default", "x86_64", "ESI", "90906690c3",
                    Set.of(0, 1, 2, 4), Set.of()),
                new Profile("AARCH64:LE:64:v8A", "aarch64", "w1", "1f2003d51f2003d5c0035fd6",
                    Set.of(0, 4, 8), Set.of()),
                new Profile("ARM:LE:32:v8", "arm", "r1", "00f020e300f020e31eff2fe1",
                    Set.of(0, 4, 8), Set.of()),
                new Profile("MIPS:BE:32:default", "mips", "a1", "000000000000000003e0000800000000",
                    Set.of(0, 4, 8, 12), Set.of(12)),
                new Profile("MIPS:LE:32:default", "mipsel", "a1", "00000000000000000800e00300000000",
                    Set.of(0, 4, 8, 12), Set.of(12)))) {
            var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(profile.language()));
            Object owner = new Object();
            var program = new ProgramDB("entry-contract", language, language.getDefaultCompilerSpec(), owner);
            int transaction = program.startTransaction("actual reference controls");
            try {
                byte[] bytes = HexFormat.of().parseHex(profile.code());
                var entry = language.getDefaultSpace().getAddress(0x1000);
                var body = new AddressSet(entry, entry.add(bytes.length - 1));
                var block = program.getMemory().createInitializedBlock("code", entry, bytes.length,
                    (byte) 0, TaskMonitor.DUMMY, false);
                block.setExecute(true);
                program.getMemory().setBytes(entry, bytes);
                if (profile.target().equals("arm")) {
                    program.getProgramContext().setValue(program.getRegister("TMode"), entry,
                        body.getMaxAddress(), java.math.BigInteger.ZERO);
                }
                require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY), "decode failed");
                for (int offset = 0; offset < bytes.length; offset++) {
                    var instruction = program.getListing().getInstructionAt(entry.add(offset));
                    require((instruction != null) == profile.starts().contains(offset), "instruction boundary differs from fixture");
                    if (instruction != null) {
                        require(instruction.isInDelaySlot() == profile.slots().contains(offset), "delay-slot premise differs");
                    }
                }
                var function = program.getFunctionManager().createFunction("incoming", entry, body, SourceType.USER_DEFINED);
                var parameter = new ParameterImpl("value", IntegerDataType.dataType,
                    program.getRegister(profile.register()), program);
                var registers = TargetRegisterMap.forTarget(profile.target());
                require(GhidraVariableStorage.stableParameter(program, function, parameter, registers,
                    TaskMonitor.DUMMY).available(), "baseline incoming register is unavailable");
                var manager = program.getReferenceManager();
                // Every destination byte distinguishes actual instruction entries,
                // offcuts, and delay slots. Sources include every body byte plus
                // an external address; offcut sources cannot establish a predecessor.
                for (int source = 0; source <= bytes.length; source++) {
                    var from = entry.add(source == bytes.length ? 0x100 : source);
                    for (int destination = 0; destination < bytes.length; destination++) {
                        var to = entry.add(destination);
                        for (var type : List.of(RefType.UNCONDITIONAL_JUMP, RefType.UNCONDITIONAL_CALL,
                                RefType.READ, RefType.DATA)) {
                            require(manager.getReference(from, to, -1) == null, "control would replace an existing reference");
                            var reference = manager.addMemoryReference(from, to, type, SourceType.USER_DEFINED, -1);
                            String context = profile.target() + " from=" + source + " to=" + destination + " type=" + type;
                            try {
                                require(reference.getReferenceType() == type, "reference type changed " + context);
                                boolean expected = !type.isFlow() ||
                                    (profile.starts().contains(destination) && !profile.slots().contains(destination) &&
                                        (destination == 0 || profile.starts().contains(source)) &&
                                        !profile.slots().contains(source));
                                var actual = GhidraVariableStorage.stableParameter(program, function, parameter,
                                    registers, TaskMonitor.DUMMY);
                                require(actual.available() == expected, "incoming reference contract violated " + context + " actual=" + actual);
                                if (!expected) {
                                    require(actual instanceof UnavailableStorage missing &&
                                        missing.reason() == OmissionReason.UNKNOWN_LIFETIME,
                                        "reference refusal lost its lifetime diagnostic " + context);
                                    require(GhidraVariableStorage.parameterPrefix(program, function, parameter,
                                        registers, actual, TaskMonitor.DUMMY).isEmpty(),
                                        "unproven entry fabricated a prefix " + context);
                                }
                                cases++;
                            }
                            finally { manager.delete(reference); }
                            require(GhidraVariableStorage.stableParameter(program, function, parameter,
                                registers, TaskMonitor.DUMMY).available(), "reference removal did not restore proof " + context);
                        }
                    }
                }
                byte[] after = new byte[bytes.length];
                program.getMemory().getBytes(entry, after);
                require(Arrays.equals(bytes, after), "reference analysis changed target bytes");
                require(function.getBody().equals(body), "reference analysis changed function body");
            }
            finally {
                program.endTransaction(transaction, false);
                program.release(owner);
            }
        }
        System.out.println("flow-entry-contract=PASS cases=" + cases + " checks=" + checks + " profiles=5");
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
