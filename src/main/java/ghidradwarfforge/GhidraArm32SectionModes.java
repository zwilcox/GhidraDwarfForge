package ghidradwarfforge;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.function.Consumer;

import ghidra.program.database.code.InstructionDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.elf.Arm32SectionModes;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.nativeapi.DwarfTarget;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;

/** Mapping evidence for allocations containing selected mixed-mode function bodies. */
public final class GhidraArm32SectionModes {
    private static final long MAX_BYTES = 256L * 1024 * 1024;
    private static final long MAX_UNITS = 1024L * 1024;

    private GhidraArm32SectionModes() { }

    public static List<Arm32SectionModes.Evidence> extract(Program program, ElfImage image,
            List<FunctionSymbol> functions, DwarfTarget target, long delta,
            TaskMonitor monitor, Consumer<String> diagnostic) throws CancelledException {
        monitor.checkCancelled();
        if (!target.name().equals("arm") || target.addressBytes() != 4 || !target.littleEndian()) return List.of();
        Register register = program.getRegister("TMode");
        if (register == null || !register.isProcessorContext() || register.getBitLength() != 1) return List.of();
        var allocations = Arm32SectionModes.allocations(image, monitor::isCancelled);
        if ((long) functions.size() * allocations.size() > 16L * 1024 * 1024) {
            diagnostic.accept("Omitted ARM32 section mappings: selection comparison budget exceeded");
            return List.of();
        }
        var selected = new HashSet<Integer>();
        long instructions = 0;
        for (var symbol : functions) {
            monitor.checkCancelled();
            try {
                var entry = address(program, Math.addExact(symbol.address(), delta));
                var function = program.getFunctionManager().getFunctionAt(entry);
                if (function == null || function.isExternal()) continue;
                int modes = 0;
                var units = program.getListing().getInstructions(function.getBody(), true);
                while (units.hasNext()) {
                    monitor.checkCancelled();
                    if (++instructions > MAX_UNITS) {
                        diagnostic.accept("Omitted ARM32 section mappings: instruction selection budget exceeded");
                        return List.of();
                    }
                    var unit = units.next();
                    int mode = mode(program.getProgramContext().getRegisterValue(register, unit.getAddress()));
                    if (mode >= 0) modes |= 1 << mode;
                }
                if (modes != 3) continue;
                // A discontiguous body may touch several allocations. Each must
                // independently prove its entire mapping extent before emission.
                for (var allocation : allocations) {
                    monitor.checkCancelled();
                    var start = address(program, Math.addExact(allocation.address(), delta));
                    var end = start.addNoWrap(allocation.size() - 1);
                    if (function.getBody().intersects(start, end)) selected.add(allocation.index());
                }
            }
            catch (Omitted | AddressOutOfBoundsException | ArithmeticException | AddressOverflowException failure) {
                diagnostic.accept("Omitted ARM32 section mapping selection for " + symbol.qualifiedDisplayName() + ": " + failure.getMessage());
            }
        }
        var result = new ArrayList<Arm32SectionModes.Evidence>();
        long bytes = 0;
        long[] units = { 0 };
        for (var allocation : allocations) {
            monitor.checkCancelled();
            if (!selected.contains(allocation.index())) continue;
            try {
                require(allocation.size() <= MAX_BYTES - bytes, "mapping byte budget exceeded");
                bytes += allocation.size();
                require(allocation.fileSize() == allocation.size(), "allocation is not completely file-backed");
                result.add(prove(program, allocation, delta, register, monitor, units));
            }
            catch (Omitted | AddressOutOfBoundsException | ArithmeticException | AddressOverflowException | MemoryAccessException failure) {
                diagnostic.accept("Omitted ARM32 section mappings for " + allocation.name() + ": " + failure.getMessage());
            }
        }
        monitor.checkCancelled();
        return List.copyOf(result);
    }

    private static Arm32SectionModes.Evidence prove(Program program, Arm32SectionModes.Allocation allocation,
            long delta, Register register, TaskMonitor monitor, long[] units)
            throws CancelledException, AddressOverflowException, MemoryAccessException {
        var start = address(program, Math.addExact(allocation.address(), delta));
        var end = start.addNoWrap(allocation.size() - 1);
        require(program.getMemory().getLoadedAndInitializedAddressSet().contains(start, end),
            "allocation has unmapped or uninitialized bytes");
        var boundaries = new ArrayList<Arm32SectionModes.Boundary>();
        MessageDigest digest;
        try { digest = MessageDigest.getInstance("SHA-256"); }
        catch (java.security.NoSuchAlgorithmException impossible) { throw new AssertionError(impossible); }
        long offset = 0;
        int previousMode = -1;
        while (offset < allocation.size()) {
            monitor.checkCancelled();
            require(++units[0] <= MAX_UNITS, "mapping code-unit budget exceeded");
            Address cursor = start.addNoWrap(offset);
            var unit = program.getListing().getCodeUnitAt(cursor);
            require(unit != null && unit.getMinAddress().equals(cursor) && unit.getLength() > 0 &&
                unit.getLength() <= allocation.size() - offset &&
                unit.getMaxAddress().equals(cursor.addNoWrap(unit.getLength() - 1)),
                "allocation is not exactly tiled by code units");
            int mode;
            int length = unit.getLength();
            if (unit instanceof Instruction instruction) {
                mode = mode(program.getProgramContext().getRegisterValue(register, cursor));
                require(mode >= 0, "instruction TMode is unknown");
                require(!instruction.isLengthOverridden() && length == instruction.getParsedLength() &&
                    (mode == 0 ? length == 4 : length == 2 || length == 4), "unsupported instruction length");
                require((cursor.getOffset() & (mode == 0 ? 3 : 1)) == 0, "unaligned decoded instruction");
                require(instruction instanceof InstructionDB, "stored decode context is unavailable");
                var original = ((InstructionDB) instruction).getOriginalPrototypeContext(register.getBaseRegister());
                require(original != null && mode(original.getRegisterValue(register)) == mode,
                    "stored instruction mode disagrees with current context");
                for (int byteIndex = 0; byteIndex < length; byteIndex++) {
                    monitor.checkCancelled();
                    require(mode(program.getProgramContext().getRegisterValue(register, cursor.addNoWrap(byteIndex))) == mode,
                        "instruction TMode is unknown or inconsistent within its bytes");
                }
                byte[] memory = new byte[length];
                require(program.getMemory().getBytes(cursor, memory) == length &&
                    Arrays.equals(memory, instruction.getParsedBytes()), "instruction bytes disagree with memory");
                digest.update(memory);
            }
            else {
                require(unit instanceof Data data && data.isDefined(), "unknown bytes cannot be mapped as data");
                mode = 2;
                byte[] memory = new byte[Math.min(length, 65536)];
                for (int done = 0; done < length;) {
                    monitor.checkCancelled();
                    int count = Math.min(memory.length, length - done);
                    require(program.getMemory().getBytes(cursor.addNoWrap(done), memory, 0, count) == count,
                        "incomplete defined data bytes");
                    digest.update(memory, 0, count);
                    done += count;
                }
            }
            if (mode != previousMode) {
                require(boundaries.size() < 65536, "mapping boundary budget exceeded");
                boundaries.add(new Arm32SectionModes.Boundary(offset, mode));
            }
            previousMode = mode;
            offset += length;
        }
        return new Arm32SectionModes.Evidence(allocation.index(), allocation.address(), allocation.size(),
            HexFormat.of().formatHex(digest.digest()), boundaries);
    }

    private static Address address(Program program, long offset) {
        require(offset >= 0 && offset <= 0xffff_ffffL, "analysis address exceeds ARM32");
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private static int mode(RegisterValue value) {
        if (value == null || !value.hasValue()) return -1;
        BigInteger integer = value.getUnsignedValue();
        return BigInteger.ZERO.equals(integer) ? 0 : BigInteger.ONE.equals(integer) ? 1 : -1;
    }

    private static final class Omitted extends RuntimeException {
        Omitted(String message) { super(message); }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new Omitted(message);
    }
}
