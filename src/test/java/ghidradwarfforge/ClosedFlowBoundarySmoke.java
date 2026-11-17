package ghidradwarfforge;

import java.io.File;
import java.math.BigInteger;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;

import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.locations.TargetRegisterMap;

/** Actual conditional transfers and saved slot references must not invent register lifetimes. */
public final class ClosedFlowBoundarySmoke {
    private static int checks;

    private ClosedFlowBoundarySmoke() { }

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        check();
    }

    static void check() throws Exception {
        checks = 0;
        // Instructions at 0x1000, followed by a NOP and an ordinary return.
        // Direct BL targets 0x2000. Its callee proof belongs to the caller of
        // closedRegisterFlow; allowing its shape is not a value-preservation proof.
        arm("ordinary-return", "1eff2fe1", false, false, true, true);
        arm("conditional-bx-return", "1eff2f01", true, false, false, false);
        arm("conditional-pop-return", "0080bd08", true, false, false, false);
        arm("direct-call", "fe0300eb", false, true, true, false);
        arm("conditional-call", "fe03000b", true, true, false, false);
        arm("computed-call", "30ff2fe1", false, true, false, false);
        for (boolean little : List.of(false, true)) {
            for (RefType reference : new RefType[] { null, RefType.DATA,
                    RefType.UNCONDITIONAL_JUMP, RefType.CONDITIONAL_JUMP,
                    RefType.UNCONDITIONAL_CALL }) {
                slotReference(little, reference);
            }
        }
        System.out.println("closed-flow-boundaries=PASS cases=16 checks=" + checks);
    }

    private static void arm(String name, String first, boolean conditional, boolean call,
            boolean closedWithCalls, boolean available) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("ARM:LE:32:v8"));
        Object owner = new Object();
        var program = new ProgramDB(name, language, language.getDefaultCompilerSpec(), owner);
        int transaction = program.startTransaction("real ARM transfers");
        try {
            byte[] bytes = HexFormat.of().parseHex(first + "00f020e31eff2fe1");
            var entry = language.getDefaultSpace().getAddress(0x1000);
            var body = new AddressSet(entry, entry.add(bytes.length - 1));
            program.getMemory().createInitializedBlock("code", entry, bytes.length, (byte) 0,
                TaskMonitor.DUMMY, false).setExecute(true);
            program.getMemory().setBytes(entry, bytes);
            program.getProgramContext().setValue(program.getRegister("TMode"), entry, body.getMaxAddress(), BigInteger.ZERO);
            for (int offset = 0; offset < bytes.length; offset += 4) {
                require(new DisassembleCommand(entry.add(offset), body, false).applyTo(program, TaskMonitor.DUMMY),
                    name + ": decode");
            }
            var function = program.getFunctionManager().createFunction(name, entry, body, SourceType.USER_DEFINED);
            var firstInstruction = program.getListing().getInstructionAt(entry);
            var flow = firstInstruction.getFlowType();
            require(flow.isConditional() == conditional && flow.isCall() == call,
                name + ": transfer premise differs: " + flow);
            require(call || flow.isTerminal(), name + ": expected a return");
            var decoded = decoded(program, body);
            require(decoded.size() == 3, name + ": complete body");
            require(GhidraVariableStorage.closedRegisterFlow(program, function, decoded, true, TaskMonitor.DUMMY)
                == closedWithCalls, name + ": direct-call shape policy");
            require(GhidraVariableStorage.closedRegisterFlow(program, function, decoded, false, TaskMonitor.DUMMY)
                == available, name + ": call-free shape policy");
            var parameter = new ParameterImpl("incoming", IntegerDataType.dataType, program.getRegister("r1"), program);
            require(GhidraVariableStorage.stableParameter(program, function, parameter,
                TargetRegisterMap.forTarget("arm"), TaskMonitor.DUMMY).available() == available,
                name + ": public stable storage policy");
        }
        finally {
            program.endTransaction(transaction, false);
            program.release(owner);
        }
    }

    private static void slotReference(boolean little, RefType reference) throws Exception {
        String name = (little ? "mipsle" : "mipsbe") + "-slot-" + reference;
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(
            little ? "MIPS:LE:32:default" : "MIPS:BE:32:default"));
        Object owner = new Object();
        var program = new ProgramDB(name, language, language.getDefaultCompilerSpec(), owner);
        int transaction = program.startTransaction("saved delay-slot references");
        try {
            byte[] bytes = HexFormat.of().parseHex(little ? "0800e00300000000" : "03e0000800000000");
            var entry = language.getDefaultSpace().getAddress(0x1000);
            var body = new AddressSet(entry, entry.add(bytes.length - 1));
            program.getMemory().createInitializedBlock("code", entry, bytes.length, (byte) 0,
                TaskMonitor.DUMMY, false).setExecute(true);
            program.getMemory().setBytes(entry, bytes);
            require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY), name + ": decode");
            var function = program.getFunctionManager().createFunction("return_with_slot", entry, body, SourceType.USER_DEFINED);
            var slot = program.getListing().getInstructionAt(entry.add(4));
            require(slot.isInDelaySlot() && slot.getFlowType().isFallthrough(), name + ": real NOP delay slot");
            if (reference != null) {
                program.getReferenceManager().addMemoryReference(slot.getAddress(), entry.add(0x1000),
                    reference, SourceType.USER_DEFINED, 0);
            }
            require(slot.getFlowType().isFallthrough(), name + ": references must not rewrite the prototype");
            boolean expected = reference == null || !reference.isFlow();
            var decoded = decoded(program, body);
            require(decoded.size() == 2, name + ": complete return and slot");
            require(GhidraVariableStorage.closedRegisterFlow(program, function, decoded, true, TaskMonitor.DUMMY)
                == expected, name + ": saved slot flow must be accounted for");
            var parameter = new ParameterImpl("incoming", IntegerDataType.dataType, program.getRegister("a1"), program);
            require(GhidraVariableStorage.stableParameter(program, function, parameter,
                TargetRegisterMap.forTarget(little ? "mipsel" : "mips"), TaskMonitor.DUMMY).available() == expected,
                name + ": public stable storage policy");
            if (reference != null) {
                program.getReferenceManager().removeAllReferencesFrom(slot.getAddress());
                require(GhidraVariableStorage.closedRegisterFlow(program, function, decoded, true, TaskMonitor.DUMMY),
                    name + ": restored listing must recover its proof");
            }
        }
        finally {
            program.endTransaction(transaction, false);
            program.release(owner);
        }
    }

    private static LinkedHashMap<Address, Instruction> decoded(ProgramDB program, AddressSet body) {
        var result = new LinkedHashMap<Address, Instruction>();
        var iterator = program.getListing().getInstructions(body, true);
        while (iterator.hasNext()) {
            var instruction = iterator.next();
            result.put(instruction.getAddress(), instruction);
        }
        return result;
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
