package ghidradwarfforge;

import java.lang.reflect.Proxy;
import java.util.List;

import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/** Checks the conservative instruction proof, including unnamed register aliases. */
public final class RegisterPrefixSmoke {
    private static final AddressSpace RAM =
        new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0);
    private static final AddressSpace REGISTERS =
        new GenericAddressSpace("register", 64, AddressSpace.TYPE_REGISTER, 1);
    private static final AddressSpace CONSTANTS =
        new GenericAddressSpace("constant", 64, AddressSpace.TYPE_CONSTANT, 2);
    private static final Register PARAMETER =
        new Register("incoming", "test incoming register", REGISTERS.getAddress(0x100),
            8, false, 0);

    private RegisterPrefixSmoke() {
    }

    public static void main(String[] args) throws Exception {
        Instruction initial = instruction(0x1000, PcodeOp.COPY, null);
        // This byte is inside the base register but has no named Ghidra alias.
        Instruction partial = instruction(0x1003, PcodeOp.COPY,
            new Varnode(REGISTERS.getAddress(0x103), 1));
        Instruction terminal = instruction(0x1006, PcodeOp.RETURN, null);
        expect(0x1006, List.of(initial, partial, terminal), 0x1009);
        expect(0x1006, List.of(initial, instruction(0x1003, PcodeOp.COPY,
            new Varnode(REGISTERS.getAddress(0xfe), 4)), terminal), 0x1009);
        // Adjacent registers are not aliases.
        expect(-1, List.of(initial, instruction(0x1003, PcodeOp.COPY,
            new Varnode(REGISTERS.getAddress(0x108), 8)), terminal), 0x1009);
        Varnode dynamicOffset = new Varnode(REGISTERS.getAddress(0x200), 8);
        Varnode value = new Varnode(CONSTANTS.getAddress(19), 1);
        for (Varnode offset : List.of(dynamicOffset,
                new Varnode(CONSTANTS.getAddress(0x103), 8))) {
            Instruction store = store(0x1003,
                new Varnode(CONSTANTS.getAddress(REGISTERS.getSpaceID()), 4), offset, value);
            expect(0x1006, List.of(initial, store, terminal), 0x1009);
            if (!GhidraVariableStorage.writesRegister(store, PARAMETER)) {
                throw new AssertionError("register-space STORE retained a stable location");
            }
        }
        Instruction memoryStore = store(0x1003,
            new Varnode(CONSTANTS.getAddress(RAM.getSpaceID()), 4), dynamicOffset, value);
        expect(-1, List.of(initial, memoryStore, terminal), 0x1009);
        if (GhidraVariableStorage.writesRegister(memoryStore, PARAMETER)) {
            throw new AssertionError("ordinary RAM STORE clobbered an incoming register");
        }
        for (Instruction malformed : List.of(instruction(0x1003, PcodeOp.STORE, null),
                store(0x1003, dynamicOffset, dynamicOffset, value),
                store(0x1003, null, dynamicOffset, value))) {
            if (!GhidraVariableStorage.writesRegister(malformed, PARAMETER)) {
                throw new AssertionError("malformed STORE retained a stable location");
            }
        }
        for (int opcode : new int[] { PcodeOp.CALL, PcodeOp.CALLIND, PcodeOp.BRANCH,
                PcodeOp.CBRANCH, PcodeOp.BRANCHIND, PcodeOp.CALLOTHER,
                PcodeOp.UNIMPLEMENTED }) {
            // A hazard after the overwrite must still reject the whole proof.
            expect(-1, List.of(initial, partial, instruction(0x1006, opcode, null),
                instruction(0x1009, PcodeOp.RETURN, null)), 0x100c);
        }
        expect(-1, List.of(initial, partial, instruction(0x1009, PcodeOp.RETURN, null)),
            0x100c); // undecoded bytes
        expect(-1, List.of(initial, partial), 0x1006); // no proven return
        expect(-1, List.of(initial, terminal, partial), 0x1009); // unordered body
        expect(-1, List.of(initial, partial, terminal), 0x100c); // undecoded tail
        expect(-1, List.of(decorate(initial, "isInDelaySlot", true), partial, terminal), 0x1009);
        expect(-1, List.of(decorate(initial, "getDelaySlotDepth", 1), partial, terminal), 0x1009);
        expect(-1, List.of(decorate(initial, "getFlowOverride", FlowOverride.CALL),
            partial, terminal), 0x1009);
        expect(-1, List.of(decorate(initial, "getFlowType", RefType.UNCONDITIONAL_CALL),
            partial, terminal), 0x1009);
        expect(-1, List.of(decorate(initial, "getFallThrough", RAM.getAddress(0x1006)),
            partial, terminal), 0x1009);
        TaskMonitorAdapter cancelled = new TaskMonitorAdapter(true);
        cancelled.cancel();
        try {
            GhidraVariableStorage.registerPrefixEnd(0x1000, 0x1009,
                List.of(initial, partial, terminal), PARAMETER, cancelled);
            throw new AssertionError("cancelled instruction proof completed");
        }
        catch (CancelledException expected) {
            // Cancellation must propagate to the real export.
        }
        System.out.println("register-prefix-smoke=PASS");
    }

    private static void expect(long expected, List<Instruction> instructions, long end)
            throws Exception {
        long actual = GhidraVariableStorage.registerPrefixEnd(0x1000, end, instructions,
            PARAMETER, TaskMonitor.DUMMY);
        if (actual != expected) {
            throw new AssertionError("prefix boundary expected " + expected + " found " + actual);
        }
    }

    private static Instruction instruction(long address, int opcode, Varnode output) {
        var at = RAM.getAddress(address);
        boolean returns = opcode == PcodeOp.RETURN;
        PcodeOp operation = new PcodeOp(at, 0, opcode, new Varnode[0], output);
        return (Instruction) Proxy.newProxyInstance(Instruction.class.getClassLoader(),
            new Class<?>[] { Instruction.class }, (proxy, method, args) ->
                switch (method.getName()) {
                    case "getAddress" -> at;
                    case "getMaxAddress" -> at.add(2);
                    case "getFallThrough" -> returns ? null : at.add(3);
                    case "isInDelaySlot" -> false;
                    case "getDelaySlotDepth" -> 0;
                    case "getFlowOverride" -> FlowOverride.NONE;
                    case "getFlowType" -> (FlowType) (returns ? RefType.TERMINATOR :
                        RefType.FALL_THROUGH);
                    case "getPcode" -> new PcodeOp[] { operation };
                    case "getResultObjects" -> new Object[0];
                    default -> throw new AssertionError("unexpected instruction API " + method);
                });
    }

    private static Instruction decorate(Instruction original, String name, Object value) {
        return (Instruction) Proxy.newProxyInstance(Instruction.class.getClassLoader(),
            new Class<?>[] { Instruction.class }, (proxy, method, args) ->
                method.getName().equals(name) ? value : method.invoke(original, args));
    }

    private static Instruction store(long address, Varnode space, Varnode offset,
            Varnode value) {
        PcodeOp operation = new PcodeOp(RAM.getAddress(address), 0, PcodeOp.STORE,
            new Varnode[] { space, offset, value }, null);
        return decorate(instruction(address, PcodeOp.COPY, null), "getPcode",
            new PcodeOp[] { operation });
    }
}
