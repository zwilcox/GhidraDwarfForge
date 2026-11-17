package ghidradwarfforge;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
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
        System.out.println("closed-flow-boundaries=PASS native-cases=16 metadata-cases=35 checks=" + checks);
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
            if (name.equals("ordinary-return")) {
                // A non-delayed ISA isolates invalid depth from MIPS's separate
                // missing-owner and slot checks.
                var invalid = new LinkedHashMap<>(decoded);
                invalid.put(entry, view(Instruction.class, firstInstruction, Map.of("getDelaySlotDepth", -1)));
                require(!GhidraVariableStorage.closedRegisterFlow(program, function, invalid, false, TaskMonitor.DUMMY),
                    "negative delay depth accepted on a non-delayed return");
                require(GhidraVariableStorage.closedRegisterFlow(program, function, decoded, false, TaskMonitor.DUMMY),
                    "invalid delay depth poisoned ordinary ARM return");
            }
        }
        finally {
            program.endTransaction(transaction, false);
            try { program.flushEvents(); }
            finally { program.release(owner); }
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
            if (reference == null) delayOwnership(program, function, decoded, bytes);
            if (reference != null) {
                program.getReferenceManager().removeAllReferencesFrom(slot.getAddress());
                require(GhidraVariableStorage.closedRegisterFlow(program, function, decoded, true, TaskMonitor.DUMMY),
                    name + ": restored listing must recover its proof");
            }
        }
        finally {
            program.endTransaction(transaction, false);
            try { program.flushEvents(); }
            finally { program.release(owner); }
        }
    }

    private static void delayOwnership(ProgramDB program, Function function,
            LinkedHashMap<Address, Instruction> original, byte[] bytes) throws Exception {
        Address entry = function.getEntryPoint();
        Instruction owner = original.get(entry), slot = original.get(entry.add(4));
        long modification = program.getModificationNumber();
        var body = new AddressSet(function.getBody());
        for (String fault : List.of("control", "null-slot-targets", "missing-entry", "negative-depth",
                "missing-slot", "unmarked-slot", "nested-slot", "owner-is-slot", "shared-slot",
                "orphan-slot", "entry-in-slot", "slot-jumps", "slot-default-target",
                "branch-into-slot", "terminal-fallthrough", "empty-return", "nonreturn-terminal")) {
            var changed = new LinkedHashMap<>(original);
            Function observed = function;
            switch (fault) {
                case "control" -> { }
                case "null-slot-targets" -> {
                    var replacements = new java.util.HashMap<String, Object>();
                    replacements.put("getFlows", null);
                    replacements.put("getDefaultFlows", null);
                    changed.put(slot.getAddress(), view(Instruction.class, slot, replacements));
                }
                case "missing-entry" -> changed.remove(entry);
                case "negative-depth" -> changed.put(entry, view(Instruction.class, owner, Map.of("getDelaySlotDepth", -1)));
                case "missing-slot" -> changed.remove(slot.getAddress());
                case "unmarked-slot" -> changed.put(slot.getAddress(), view(Instruction.class, slot, Map.of("isInDelaySlot", false)));
                case "nested-slot" -> changed.put(slot.getAddress(), view(Instruction.class, slot, Map.of("getDelaySlotDepth", 1)));
                case "owner-is-slot" -> changed.put(entry, view(Instruction.class, owner, Map.of("isInDelaySlot", true)));
                case "shared-slot" -> {
                    // Two observations claim the same physical slot. The second
                    // owner keeps its extent so ownership fails before CFG edges.
                    Address extra = entry.add(8);
                    changed.put(extra, view(Instruction.class, owner, Map.of("getAddress", extra)));
                }
                case "orphan-slot" -> changed.put(entry, view(Instruction.class, owner, Map.of("getDelaySlotDepth", 0)));
                case "entry-in-slot" -> observed = view(Function.class, function, Map.of("getEntryPoint", slot.getAddress()));
                case "slot-jumps" -> changed.put(slot.getAddress(), view(Instruction.class, slot,
                    Map.of("getFlowType", RefType.UNCONDITIONAL_JUMP)));
                case "slot-default-target" -> changed.put(slot.getAddress(), view(Instruction.class, slot,
                    Map.of("getDefaultFlows", new Address[] { entry })));
                case "branch-into-slot" -> changed.put(entry, view(Instruction.class, owner,
                    Map.of("getDefaultFlows", new Address[] { slot.getAddress() })));
                case "terminal-fallthrough" -> changed.put(entry, view(Instruction.class, owner,
                    Map.of("getFallThrough", slot.getAddress())));
                case "empty-return" -> changed.put(entry, view(Instruction.class, owner,
                    Map.of("getPcode", new PcodeOp[0])));
                case "nonreturn-terminal" -> {
                    var register = program.getRegister("a1");
                    var node = new Varnode(register.getAddress(), register.getMinimumByteSize());
                    changed.put(entry, view(Instruction.class, owner, Map.of("getPcode", new PcodeOp[] {
                        new PcodeOp(entry, 0, PcodeOp.COPY, new Varnode[] { node }, node) })));
                }
                default -> throw new AssertionError(fault);
            }
            boolean expected = fault.equals("control") || fault.equals("null-slot-targets");
            var snapshot = Map.copyOf(changed);
            for (boolean calls : List.of(false, true)) {
                require(GhidraVariableStorage.closedRegisterFlow(program, observed, changed, calls, TaskMonitor.DUMMY)
                    == expected, "delay ownership " + fault + " / calls=" + calls);
            }
            require(changed.keySet().equals(snapshot.keySet()) && snapshot.entrySet().stream()
                .allMatch(item -> changed.get(item.getKey()) == item.getValue()), "proof modified input graph");
            require(program.getModificationNumber() == modification && function.getBody().equals(body),
                "delay ownership check modified saved program");
            byte[] actual = new byte[bytes.length];
            require(program.getMemory().getBytes(entry, actual) == actual.length && java.util.Arrays.equals(bytes, actual),
                "delay ownership check changed code bytes");
            require(GhidraVariableStorage.closedRegisterFlow(program, function, original, false, TaskMonitor.DUMMY),
                "delay ownership refusal poisoned valid retry");
        }
    }

    private static <T> T view(Class<T> type, T original, Map<String, Object> replacements) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] { type }, (proxy, method, args) -> {
            if (replacements.containsKey(method.getName())) return replacements.get(method.getName());
            try { return method.invoke(original, args); }
            catch (InvocationTargetException failure) { throw failure.getCause(); }
        }));
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
