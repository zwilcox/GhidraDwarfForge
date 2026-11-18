package ghidradwarfforge.targets;

import ghidra.program.model.data.*;
import ghidra.program.model.lang.DynamicVariableStorage;
import ghidra.program.model.listing.*;

/** Public storage objects exercise the proof independently of compiler allocation. */
public final class I386StackInputProofSmoke {
    private I386StackInputProofSmoke() { }

    public static void run(Program program) throws Exception {
        var manager = program.getDataTypeManager();
        var integer = new IntegerDataType(manager);
        var extended = new LongDoubleDataType(manager);
        var stack = program.getAddressFactory().getStackSpace();
        var prior = new VariableStorage(program, stack.getAddress(500), 4);
        var freed = new VariableStorage(program, stack.getAddress(500), 4);
        var shifted = new VariableStorage(program, stack.getAddress(496), 4);
        var indirect = new DynamicVariableStorage(program, true, freed.getVarnodes());
        var automatic = new DynamicVariableStorage(program, AutoParameterType.RETURN_STORAGE_PTR, freed.getVarnodes());
        check(freed, VariableStorage.UNASSIGNED_STORAGE, integer, true, "new full-value slot");
        check(new VariableStorage(program, stack.getAddress(492), 10), VariableStorage.UNASSIGNED_STORAGE,
            extended, true, "x87 value width without aligned padding");
        check(new VariableStorage(program, stack.getAddress(500), 2), VariableStorage.UNASSIGNED_STORAGE,
            integer, false, "partial carrier cannot prove a complete value");
        check(freed, VariableStorage.UNASSIGNED_STORAGE, extended, false, "integer-sized carrier cannot stand in for x87 value");
        check(freed, VariableStorage.UNASSIGNED_STORAGE, new FunctionDefinitionDataType("NonObject", manager),
            false, "non-object formal type supplies no value width");
        check(indirect, VariableStorage.UNASSIGNED_STORAGE, integer, false, "unknown prior cannot justify forced indirection");
        check(automatic, prior, integer, false, "automatic carrier cannot replace an explicit argument");
        check(new VariableStorage(program, program.getRegister("EAX")), prior, integer, false, "register is not a stack argument");
        check(new VariableStorage(program, stack.getAddress(0), 4), prior, integer, false, "return address is not argument storage");
        check(new VariableStorage(program, stack.getAddress(-4), 4), prior, integer, false, "local stack slot is not argument storage");
        check(shifted, prior, integer, true, "known carrier shifts toward entry stack pointer");
        check(prior, prior, integer, true, "already aligned carrier may retain its offset");
        check(new VariableStorage(program, stack.getAddress(504), 4), prior, integer, false, "correction cannot shift away from removed pointer");
        check(new VariableStorage(program, stack.getAddress(496), 2), prior, integer, false, "known value cannot shrink");
        check(indirect, prior, integer, false, "direct to indirect mutation");
        check(freed, indirect, integer, false, "indirect to direct mutation");
        check(indirect, indirect, integer, true, "proven existing indirect representation retained");
        System.out.println("i386-stack-input-proof=PASS checks=17");
    }

    private static void check(VariableStorage replacement, VariableStorage prior, DataType type,
            boolean expected, String label) {
        if (I386ParameterAllocation.provenStackInput(replacement, prior, type) != expected) {
            throw new AssertionError("i386 storage proof: " + label);
        }
    }
}
