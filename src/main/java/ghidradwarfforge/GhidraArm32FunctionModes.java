package ghidradwarfforge;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;

import ghidra.program.database.code.InstructionDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.elf.ElfFunctionModeCue;
import ghidradwarfforge.nativeapi.DwarfTarget;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;

/**
 * Narrow ARM32 ELF mode evidence from existing decoded instructions. No decoding,
 * context repair, DWARF address tagging, or inference across gaps is performed.
 * Diagnostics are enabled by a known Thumb entry, not a claim to detect every
 * mixed-mode body. ARM-only selections retain their previous output and reports.
 */
public final class GhidraArm32FunctionModes {
    private GhidraArm32FunctionModes() {
    }

    public static List<ElfFunctionModeCue> extract(Program program,
            List<FunctionSymbol> functions, DwarfTarget target, long rebaseDelta,
            TaskMonitor monitor, Consumer<String> diagnostic) throws CancelledException {
        Objects.requireNonNull(program, "program");
        Objects.requireNonNull(functions, "functions");
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(monitor, "monitor");
        Objects.requireNonNull(diagnostic, "diagnostic");
        monitor.checkCancelled();
        if (!target.name().equals("arm") || target.addressBytes() != 4 ||
                !target.littleEndian()) {
            return List.of();
        }
        Register modeRegister = program.getRegister("TMode");
        if (modeRegister == null || !modeRegister.isProcessorContext() ||
                modeRegister.getBitLength() != 1) {
            return List.of();
        }
        List<Selected> selected = new ArrayList<>();
        boolean knownThumbEntry = false;
        var ordered = functions.stream().sorted(Comparator.comparingLong(FunctionSymbol::address)
            .thenComparing(FunctionSymbol::qualifiedDisplayName)).toList();
        for (FunctionSymbol symbol : ordered) {
            monitor.checkCancelled();
            Address entry;
            try {
                long analysisOffset = Math.addExact(symbol.address(), rebaseDelta);
                require(analysisOffset >= 0 && analysisOffset <= 0xffff_ffffL,
                    "analysis entry is outside ARM32 addresses");
                entry = program.getAddressFactory().getDefaultAddressSpace()
                    .getAddress(analysisOffset);
            }
            catch (Omitted | ArithmeticException | AddressOutOfBoundsException failure) {
                selected.add(new Selected(symbol, null, -1, failure.getMessage()));
                continue;
            }
            int entryMode = mode(program.getProgramContext().getRegisterValue(modeRegister, entry));
            knownThumbEntry |= entryMode == 1;
            selected.add(new Selected(symbol, entry, entryMode, null));
        }
        monitor.checkCancelled();
        if (!knownThumbEntry) {
            return List.of();
        }
        List<ElfFunctionModeCue> cues = new ArrayList<>();
        List<String> omissions = new ArrayList<>();
        for (Selected item : selected) {
            monitor.checkCancelled();
            String reason = item.issue();
            if (reason == null) {
                try {
                    cues.add(prove(program, item.symbol(), item.entry(), modeRegister,
                        item.mode(), monitor));
                }
                catch (Omitted | AddressOverflowException | MemoryAccessException failure) {
                    reason = failure.getMessage();
                }
            }
            if (reason != null) {
                omissions.add("Omitted ARM32 function mode cue for " +
                    item.symbol().qualifiedDisplayName() + ": " + reason);
            }
        }
        for (String omission : omissions) {
            monitor.checkCancelled();
            diagnostic.accept(omission);
        }
        monitor.checkCancelled();
        return cues.stream().anyMatch(cue -> (cue.symbolValue() & 1) != 0)
            ? List.copyOf(cues) : List.of();
    }

    private static ElfFunctionModeCue prove(Program program, FunctionSymbol symbol,
            Address entry, Register modeRegister, int entryMode, TaskMonitor monitor)
            throws Omitted, AddressOverflowException, MemoryAccessException, CancelledException {
        Function function = program.getFunctionManager().getFunctionAt(entry);
        require(function != null && !function.isExternal() && !function.isThunk(),
            "selected memory definition is unavailable");
        require(function.getName().equals(symbol.name()), "selected function name changed");
        var body = function.getBody();
        require(symbol.contiguous() && body.getNumAddressRanges() == 1 &&
            body.getMinAddress().equals(entry) && function.getEntryPoint().equals(entry),
            "requires a contiguous entry-first body");
        long size = body.getNumAddresses();
        require(symbol.ranges().get(0).address() == symbol.address() &&
            symbol.ranges().get(0).size() == size, "selected function body changed");
        require(symbol.address() <= 0xffff_ffffL && size > 0 &&
            size <= 0x1_0000_0000L - symbol.address(),
            "function extent is outside ELF32 addresses");
        require(entryMode == 0 || entryMode == 1, "entry TMode is not fully known");
        require((symbol.address() & (entryMode == 0 ? 3 : 1)) == 0,
            "entry does not have the decoded instruction alignment");
        Register baseContext = modeRegister.getBaseRegister();
        MessageDigest digest = sha256();
        long remaining = size;
        Address cursor = entry;
        var instructions = program.getListing().getInstructions(body, true);
        while (instructions.hasNext()) {
            monitor.checkCancelled();
            var instruction = instructions.next();
            require(remaining > 0 && instruction.getAddress().equals(cursor),
                "body is not exactly tiled by decoded instructions");
            int length = instruction.getLength();
            require(!instruction.isLengthOverridden() && length == instruction.getParsedLength() &&
                (entryMode == 0 ? length == 4 : length == 2 || length == 4) && length <= remaining,
                "unsupported or overridden instruction length");
            require(instruction.getMaxAddress().equals(cursor.addNoWrap(length - 1)),
                "decoded instruction extent disagrees with its length");
            require(instruction instanceof InstructionDB,
                "stored instruction decode context is unavailable");
            // Instruction.getRegisterValue reads mutable ProgramContext. The pinned
            // DB API instead retrieves the context saved with the shared prototype.
            // That store retains values, not original validity masks; require fully
            // known current TMode at every byte as well as saved decode-mode agreement.
            RegisterValue original = ((InstructionDB) instruction)
                .getOriginalPrototypeContext(baseContext);
            require(original != null && mode(original.getRegisterValue(modeRegister)) == entryMode,
                "stored instruction decode mode disagrees with entry TMode");
            for (int offset = 0; offset < length; offset++) {
                monitor.checkCancelled();
                require(mode(program.getProgramContext().getRegisterValue(
                    modeRegister, cursor.addNoWrap(offset))) == entryMode,
                    "instruction TMode is unknown or mixed within the body");
            }
            // These are current bytes, not an immutable history of decoding.
            // Pinned ordinary memory writes reject existing instructions; clearing
            // them before a patch causes the tiling check above to fail. The ELF
            // planner separately compares this digest with the selected original.
            byte[] parsed = instruction.getParsedBytes();
            byte[] memory = new byte[length];
            require(parsed.length == length && program.getMemory().getBytes(cursor, memory) == length &&
                Arrays.equals(parsed, memory), "instruction and memory bytes disagree");
            digest.update(memory);
            remaining -= length;
            if (remaining != 0) {
                cursor = cursor.addNoWrap(length);
            }
        }
        require(remaining == 0, "body has bytes without decoded instructions");
        monitor.checkCancelled();
        return new ElfFunctionModeCue(symbol.qualifiedDisplayName(), symbol.address(), size,
            symbol.address() | entryMode, HexFormat.of().formatHex(digest.digest()));
    }

    private static int mode(RegisterValue value) {
        if (value == null || !value.hasValue()) {
            return -1;
        }
        BigInteger unsigned = value.getUnsignedValue();
        return BigInteger.ZERO.equals(unsigned) ? 0 : BigInteger.ONE.equals(unsigned) ? 1 : -1;
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        }
        catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private static void require(boolean condition, String message) throws Omitted {
        if (!condition) {
            throw new Omitted(message);
        }
    }

    private static final class Omitted extends Exception {
        Omitted(String message) {
            super(message);
        }
    }

    private record Selected(FunctionSymbol symbol, Address entry, int mode, String issue) {
    }
}
