package ghidradwarfforge;

import java.nio.ByteOrder;
import java.util.LinkedHashSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.Varnode;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.RegisterStorage;

/** A physical byte span need not have a named language alias. */
final class RegisterByteSlice {
    record View(Register container, RegisterStorage storage) { }

    private RegisterByteSlice() { }

    static boolean contains(Register register, Varnode node) {
        if (register == null || node == null || !node.isRegister() || node.getSize() <= 0 ||
                register.getBitLength() % Byte.SIZE != 0 ||
                !register.getAddress().getAddressSpace().equals(node.getAddress().getAddressSpace())) return false;
        long offset = node.getAddress().subtract(register.getAddress());
        return offset >= 0 && offset <= register.getMinimumByteSize() - node.getSize();
    }

    /** Only for physical write/call-effect guards, independently of DWARF numbering. */
    static Register container(Program program, Varnode node) {
        if (node == null || !node.isRegister()) return null;
        Register direct = program.getRegister(node);
        if (contains(direct, node)) return direct;
        Register best = null;
        for (Register candidate : program.getLanguage().getRegisters()) {
            if (contains(candidate, node) && (best == null || candidate.getBitLength() < best.getBitLength())) best = candidate;
        }
        return best;
    }

    static View mapped(Program program, Varnode node, TargetRegisterMap registers) {
        if (node == null || !node.isRegister() || node.getSize() <= 0) return null;
        var names = new LinkedHashSet<String>();
        Register direct = program.getRegister(node);
        if (direct != null) names.add(direct.getName());
        names.addAll(registers.registerSlices().keySet());
        names.addAll(registers.dwarfNumbers().keySet());
        View best = null;
        for (String name : names) {
            Register candidate = program.getLanguage().getRegister(name);
            if (!contains(candidate, node) || (best != null &&
                    best.container().getBitLength() <= candidate.getBitLength())) continue;
            var whole = GhidraVariableStorage.mappedRegister(candidate, candidate.getMinimumByteSize(), registers,
                "physical register byte span");
            if (!(whole instanceof RegisterStorage register)) continue;
            long delta = node.getAddress().subtract(candidate.getAddress());
            boolean big = registers.registerStorageByteOrder() == null ? candidate.isBigEndian() :
                registers.registerStorageByteOrder() == ByteOrder.BIG_ENDIAN;
            int offset = Math.toIntExact(big ? candidate.getMinimumByteSize() - delta - node.getSize() : delta);
            best = new View(candidate, new RegisterStorage(register.register(),
                Math.addExact(register.valueBitOffset(), Math.multiplyExact(offset, Byte.SIZE)),
                Math.multiplyExact(node.getSize(), Byte.SIZE)));
        }
        return best;
    }
}
